"""tonic servers in the gRPC service x interceptor matrix: tower layers, per-service
interceptors, trait methods, diagnostic services and the gaps."""

from __future__ import annotations

from pathlib import Path

from traust_core.v1.providers import tonic_services
from traust_core.v1.providers.grpc_guards import grpc_guards
from traust_core.v1.providers.tree import tree_files

IMPL = (
    "#[tonic::async_trait]\nimpl Greeter for MyGreeter {\n"
    "    async fn say_hello(&self, r: Request<Hi>) -> Result<Response<Bye>, Status> { todo!() }\n"
    "    async fn watch(&self, r: Request<Streaming<Hi>>) -> Result<Response<S>, Status> "
    "{ todo!() }\n}\n"
)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _fact(root: Path) -> dict:
    return grpc_guards(tree_files(root)).model_dump(mode="json")


def test_a_service_on_a_bare_server_is_judged_with_its_methods(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use tonic::transport::Server;\n" + IMPL + "async fn run() {\n"
        "    Server::builder().add_service(GreeterServer::new(MyGreeter::default()))"
        ".serve(addr).await?;\n}\n",
    )
    fact = _fact(tmp_path)
    [svc] = fact["services"]
    assert svc["framework"] == "tonic" and svc["service"] == "Greeter"
    assert svc["methods"] == ["say_hello", "watch"] and svc["streams"] == ["watch"]
    assert svc["judgement_required"] and svc["methods_known"]
    assert svc["implementation"] == "MyGreeter::default()"
    assert fact["coverage_gaps"] == []


def test_server_layers_and_per_service_interceptors_guard(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use tonic::transport::Server;\n" + IMPL + "async fn run() {\n"
        "    let admin = InterceptedService::new(AdminServer::new(MyAdmin), check_auth);\n"
        "    Server::builder()\n"
        "        .layer(TraceLayer::new_for_grpc())\n"
        "        .add_service(GreeterServer::with_interceptor(MyGreeter, verify_token))\n"
        "        .add_service(admin)\n"
        "        .add_service(StatusServer::new(MyStatus))\n"
        "        .serve(addr).await?;\n}\n",
    )
    services = {s["service"]: s for s in _fact(tmp_path)["services"]}
    greeter = services["Greeter"]
    assert not greeter["judgement_required"]
    assert {i["expr"] for i in greeter["interceptors"]} == {"verify_token"}
    assert not services["Admin"]["judgement_required"]
    assert services["Status"]["judgement_required"]
    assert services["Status"]["judgement_reasons"][-1].endswith("methods unknown")


def test_an_auth_layer_guards_every_service_on_the_server(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use tonic::transport::Server;\n" + IMPL + "async fn run() {\n"
        "    Server::builder().layer(AuthLayer::new(keys))"
        ".add_service(GreeterServer::new(MyGreeter)).serve(addr).await?;\n}\n",
    )
    fact = _fact(tmp_path)
    [server] = fact["servers"]
    assert server["unary_guarded"] and server["stream_guarded"]
    assert not fact["services"][0]["judgement_required"]


def test_reflection_and_health_are_exposures(tmp_path):
    _write(
        tmp_path,
        "src/main.rs",
        "use tonic::transport::Server;\nasync fn run() {\n"
        "    let (_, health) = tonic_health::server::health_reporter();\n"
        "    let reflection = tonic_reflection::server::Builder::configure().build_v1()?;\n"
        "    Server::builder().add_service(health).add_service(reflection)"
        ".serve(addr).await?;\n}\n",
    )
    kinds = sorted(e["kind"] for e in _fact(tmp_path)["exposures"])
    assert kinds == ["health", "reflection"]


def test_without_the_rust_grammar_tonic_is_a_named_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(tonic_services, "parser", lambda: None)
    _write(tmp_path, "src/main.rs", "use tonic::transport::Server;\n")
    [gap] = _fact(tmp_path)["coverage_gaps"]
    assert gap["system"] == "tonic" and "tree-sitter-rust" in gap["reason"]


def test_tonic_without_a_server_builder_is_a_gap(tmp_path):
    _write(tmp_path, "src/client.rs", "use tonic::Request;\nfn call() {}\n")
    [gap] = _fact(tmp_path)["coverage_gaps"]
    assert gap["system"] == "tonic" and "UNENUMERATED" in gap["reason"]
