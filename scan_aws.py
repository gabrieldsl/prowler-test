#!/usr/bin/env python3
"""Executa todos os checks AWS do Prowler usando profiles locais."""

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from inspect import signature
from pathlib import Path


@contextmanager
def aws_tls(no_verify_ssl):
    """Altera apenas os clientes Botocore criados neste processo/contexto."""
    if not no_verify_ssl:
        yield
        return
    from botocore.session import Session

    original = Session.create_client
    client_signature = signature(original)

    def create_client(*args, **kwargs):
        # Inclui clientes internos de STS/AssumeRole e SSO criados pelo SDK.
        bound = client_signature.bind(*args, **kwargs)
        bound.arguments["verify"] = False
        return original(*bound.args, **bound.kwargs)

    Session.create_client = create_client
    try:
        yield
    finally:
        Session.create_client = original


def command(profile, output, no_verify_ssl=False):
    # Sem filtros de checks, servicos, compliance, severidade ou regioes.
    prefix = [sys.executable, "-m", "prowler"]
    if no_verify_ssl:
        # O worker instala a mesma configuracao antes de importar o Prowler.
        prefix = [sys.executable, str(Path(__file__).resolve()), "--_prowler-worker"]
    return prefix + [
        "aws", "--profile", profile,
        "--scan-unused-services", "--output-modes", "html", "csv", "json-ocsf",
        "--output-directory", str(output),
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--profiles", nargs="+", help="Profiles AWS para varrer.")
    selection.add_argument("--all-profiles", action="store_true", help="Varrer todos os profiles locais.")
    selection.add_argument("--list-profiles", action="store_true", help="Listar profiles e sair.")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="Pasta de saida (padrao: reports).")
    parser.add_argument("--dry-run", action="store_true", help="Mostrar comandos sem acessar a AWS.")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Desativar validacao dos certificados nas chamadas AWS desta execucao.")
    args = parser.parse_args(argv)
    if not (args.profiles or args.all_profiles or args.list_profiles):
        parser.error("informe --profiles NOME, --all-profiles ou --list-profiles")

    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        parser.error("instale as dependencias: python -m pip install -r requirements.txt")

    try:
        available = boto3.Session().available_profiles
    except BotoCoreError as exc:
        print(f"Erro ao ler profiles AWS: {exc}", file=sys.stderr)
        return 1
    if args.list_profiles:
        print("\n".join(available) if available else "Nenhum profile AWS encontrado.")
        return 0
    profiles = list(dict.fromkeys(args.profiles or available))
    if not profiles:
        parser.error("nenhum profile AWS encontrado")
    missing = [profile for profile in profiles if profile not in available]
    if missing:
        parser.error("profiles inexistentes: " + ", ".join(missing))
    if not args.dry_run and importlib.util.find_spec("prowler") is None:
        parser.error("Prowler ausente neste Python; execute python -m pip install -r requirements.txt")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    root = args.output_dir.resolve() / timestamp
    results = []
    if args.no_verify_ssl:
        print("AVISO: validacao de certificados desativada nas chamadas AWS desta execucao.", flush=True)
    for index, profile in enumerate(profiles, start=1):
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", profile)[:70] or "profile"
        output = root / f"{index:02d}_{safe_name}"
        cmd = command(profile, output, args.no_verify_ssl)
        print(f"\n[{index}/{len(profiles)}] Profile: {profile}", flush=True)
        print("Comando: " + subprocess.list2cmdline(cmd), flush=True)
        if args.dry_run:
            continue

        result = {"profile": profile, "output": str(output), "tls_verification": not args.no_verify_ssl}
        output.mkdir(parents=True, exist_ok=True)
        try:
            with aws_tls(args.no_verify_ssl):
                session = boto3.Session(profile_name=profile)
                sts = session.client(
                    "sts", region_name=session.region_name or "us-east-1",
                    config=Config(connect_timeout=10, read_timeout=30, retries={"max_attempts": 2}),
                )
                with closing(sts):
                    identity = sts.get_caller_identity()
            result["account_id"] = identity["Account"]
            print(f"Conta: {identity['Account']} | Identidade: {identity['Arn']}", flush=True)
            code = subprocess.run(cmd, check=False).returncode
            result["prowler_exit_code"] = code
            result["status"] = {0: "concluido", 3: "concluido_com_achados"}.get(code, "erro")
        except (BotoCoreError, ClientError, OSError) as exc:
            result.update(status="erro", error=str(exc))
            print(f"Erro no profile {profile}: {exc}", file=sys.stderr, flush=True)
        results.append(result)
        (root / "resumo.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Resultado: {result['status']} | Saida: {output}", flush=True)

    if args.dry_run:
        print("\nSimulacao concluida. Nenhuma chamada AWS ou arquivo de relatorio criado.")
        return 0
    print(f"\nResumo: {root / 'resumo.json'}", flush=True)
    # Erros operacionais prevalecem sobre achados de seguranca.
    if any(item["status"] == "erro" for item in results):
        return 1
    return 3 if any(item["status"] == "concluido_com_achados" for item in results) else 0


if __name__ == "__main__":
    try:
        if sys.argv[1:2] == ["--_prowler-worker"]:
            # Worker privado: configuracao local, sem alterar o pacote instalado.
            with aws_tls(True):
                sys.argv = ["prowler", *sys.argv[2:]]
                from prowler.__main__ import prowler

                sys.exit(prowler())
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nExecucao interrompida. Os relatorios da conta atual podem estar incompletos.", file=sys.stderr)
        sys.exit(130)
    except OSError as exc:
        print(f"Erro local de execucao ou escrita: {exc}", file=sys.stderr)
        sys.exit(1)
