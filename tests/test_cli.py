import sys

from dosev.cli import main


def test_main_loads_config_and_starts_server(monkeypatch):
    called = {}

    monkeypatch.setattr("dosev.cli.load_config", lambda path: {
        "listen_ip": "127.0.0.1",
        "listen_port": 5353,
        "upstream_dns": "1.1.1.1",
        "protocol": "udp",
    })

    def fake_run_server_sync(**kwargs):
        called.update(kwargs)

    monkeypatch.setattr("dosev.cli.run_server_sync", fake_run_server_sync)
    monkeypatch.setattr(sys, "argv", ["dosev", "--config", "custom.conf"])

    main()

    assert called["listen_ip"] == "127.0.0.1"
    assert called["listen_port"] == 5353


def test_main_exits_on_config_error(monkeypatch):
    monkeypatch.setattr("dosev.cli.load_config", lambda path: (_ for _ in ()).throw(RuntimeError("bad config")))
    monkeypatch.setattr(sys, "argv", ["dosev"])

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 1
    else:
        assert False, "main() should exit on config errors"


def test_main_check_config_flag(monkeypatch, capsys, tmp_path):
    cfg_path = tmp_path / "dosev.conf"
    cfg_path.write_text("[server]\nlisten_port = 53\n", encoding="utf-8")

    monkeypatch.setattr("dosev.cli.load_config", lambda path: {"listen_ip": "0.0.0.0", "listen_port": 53, "upstream_dns": "1.1.1.1", "protocol": "udp"})
    monkeypatch.setattr("dosev.cli.run_server_sync", lambda **kwargs: (_ for _ in ()).throw(AssertionError("server should not start")))
    monkeypatch.setattr(sys, "argv", ["dosev", "--config", str(cfg_path), "--check-config"])

    main()

    captured = capsys.readouterr()
    assert "Configuration is valid." in captured.out
