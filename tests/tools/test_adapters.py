from __future__ import annotations

from gesicht.core.models import Host, Service
from gesicht.tools.adapters.amass import AmassAdapter
from gesicht.tools.adapters.nmap import NmapAdapter
from gesicht.tools.base import Task

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25.1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_parses_open_services(make_ws, tmp_path):
    ws = make_ws("acme.com")
    outdir = tmp_path / "out"
    outdir.mkdir()
    task = Task(targets=["example.com"], workspace=ws, outdir=outdir)
    task.artifact("nmap.xml").write_text(NMAP_XML)

    recs = list(NmapAdapter().parse(tmp_path / "raw.txt", task))
    hosts = [r for r in recs if isinstance(r, Host)]
    svcs = [r for r in recs if isinstance(r, Service)]
    assert hosts[0].hostname == "example.com" and hosts[0].ips == ["93.184.216.34"]
    assert {s.port for s in svcs} == {80, 443}  # 22 was closed
    assert svcs[0].product == "nginx"


def test_nmap_build_command_ports_and_rate(make_ws, tmp_path):
    ws = make_ws("acme.com")
    task = Task(
        targets=["10.0.0.1"], workspace=ws, outdir=tmp_path,
        rate=5.0, options={"ports": "80,443"},
    )
    argv = NmapAdapter().build_command(task, "/usr/bin/nmap")
    assert "-p" in argv and "80,443" in argv
    assert "--max-rate" in argv
    assert argv[-1] == "10.0.0.1"


def test_amass_parses_names_file(make_ws, tmp_path):
    ws = make_ws("acme.com")
    outdir = tmp_path / "out"
    outdir.mkdir()
    task = Task(targets=["acme.com"], workspace=ws, outdir=outdir)
    task.artifact("amass-names.txt").write_text(
        "www.acme.com\napi.acme.com\nwww.acme.com\n\ngarbage line !!!\n"
    )
    hosts = list(AmassAdapter().parse(tmp_path / "raw.txt", task))
    assert sorted(h.hostname for h in hosts) == ["api.acme.com", "www.acme.com"]
    assert all(h.sources == ["amass"] for h in hosts)


def test_amass_command_is_passive(make_ws, tmp_path, monkeypatch):
    ws = make_ws("acme.com")
    task = Task(targets=["acme.com", "acme.net"], workspace=ws, outdir=tmp_path)
    adapter = AmassAdapter()

    for major in (4, 5):  # v3/v4 single-step and v5 two-step layouts
        monkeypatch.setattr(adapter, "_major", lambda _b, m=major: m)
        steps = adapter.build_steps(task, "/usr/bin/amass")
        assert steps[0][1] == "enum" and "-passive" in steps[0]
        assert all(s[1] in {"enum", "subs"} for s in steps)  # never an active verb
        assert all("-d" in s and "acme.com,acme.net" in s for s in steps)
