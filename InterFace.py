import sys
import subprocess
import socket
import time
import flet as ft
from flet import Row, Column, Text, TextField


def main(page: ft.Page) -> None:
    page.title = "control"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.theme_mode=ft.ThemeMode.DARK
    page.window_width = 40
    page.window_height = 50
    page.window_resizable = False

    button_death: ft.Button = ft.Button(content=ft.Text("death"), width=200)
    button_kill: ft.Button = ft.Button(content=ft.Text("kill"), width=200)
    button_stop: ft.Button = ft.Button(content=ft.Text("stop"), width=200, disabled=True)
    button_go: ft.Button = ft.Button(content=ft.Text("go"), width=200, disabled=False)
    button_onoff: ft.Button = ft.Button(content=ft.Text("freeze"), width=200)
    text_password: TextField = TextField(label="Password", width=200)
    button_conform: ft.Button = ft.Button(content=ft.Text("confirm"), width=200, disabled=True)
    status_text: Text = Text(value="Server: not running")

    password = ""
    server_proc = None

    # Must match server.py control channel
    CONTROL_HOST = "127.0.0.1"
    CONTROL_PORT = 50099
    CONTROL_TOGGLE_STOP = b"toggle_stop_sender"
    CONTROL_TOGGLE_GO = b"toggle_go_sender"
    CONTROL_FREEZE = b"freeze_ten_times"
    CONTROL_UNFREEZE = b"unfreeze_ten_times"
    CONTROL_DEATH = b"death_message"

    # Prefix: UI sends b"set_password:" + password_bytes
    CONTROL_SET_PASSWORD_PREFIX = b"set_password:"

    def con(e: ft.ControlEvent) -> None:
        # Enable confirm only when the user typed something
        if text_password.value and text_password.value.strip():
            button_conform.disabled = False
        else:
            button_conform.disabled = True
        page.update()

    def change_onoff_text(e: ft.ControlEvent):
        # With ft.Button, the label lives in e.control.content (a ft.Text)
        # If the button currently shows "freeze", clicking it should send FREEZE,
        # then flip the label to "unfreeze". Otherwise, send UNFREEZE and flip back.
        if isinstance(e.control.content, ft.Text):
            if e.control.content.value == "freeze":
                send_freeze_unfreeze_ui(True)
                e.control.content.value = "unfreeze"
            else:
                send_freeze_unfreeze_ui(False)
                e.control.content.value = "freeze"
        page.update()

    def pa(e: ft.ControlEvent) -> None:
        nonlocal password, server_proc
        password = text_password.value

        # Send password to the server over the localhost control channel.
        # We retry briefly because the server process might need a moment to bind.
        def _send_password_to_server(pw: str) -> None:
            try:
                pw_bytes = (pw or "").encode("utf-8")
            except Exception:
                pw_bytes = b""

            payload = CONTROL_SET_PASSWORD_PREFIX + pw_bytes

            for _ in range(10):
                s = None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(payload, (CONTROL_HOST, CONTROL_PORT))
                    break
                except Exception:
                    try:
                        time.sleep(0.1)
                    except Exception:
                        pass
                finally:
                    try:
                        if s is not None:
                            s.close()
                    except Exception:
                        pass

        # If server already running, do nothing
        if server_proc is not None and server_proc.poll() is None:
            status_text.value = "Server: already running"
            page.update()
            return

        try:
            # Start server without opening another UI
            server_proc = subprocess.Popen([
                sys.executable,
                "server.py",
                "--no-ui"
            ])
            status_text.value = "Server: running"
            _send_password_to_server(password)
        except Exception as ex:
            status_text.value = f"Server failed: {ex}"

        page.update()


    def toggle_stop_sender_ui(e: ft.ControlEvent) -> None:
        """Tell the server to toggle STOP loop, and update UI state."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(CONTROL_TOGGLE_STOP, (CONTROL_HOST, CONTROL_PORT))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

        # UI: after STOP is pressed, enable GO and disable STOP
        button_go.disabled = False
        button_stop.disabled = True
        page.update()

    def toggle_go_sender_ui() -> None:
        """Ask the server process to toggle sending 'go' once per second."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(CONTROL_TOGGLE_GO, (CONTROL_HOST, CONTROL_PORT))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    def toggle_go_sender_click(e: ft.ControlEvent) -> None:
        """Tell the server to toggle GO loop, and update UI state."""
        toggle_go_sender_ui()

        # UI: after GO is pressed, enable STOP and disable GO
        button_stop.disabled = False
        button_go.disabled = True
        page.update()

    def send_freeze_unfreeze_ui(is_freeze: bool) -> None:
        """Tell the server to send 'freeze' or 'unfreeze' ten times."""
        payload = CONTROL_FREEZE if is_freeze else CONTROL_UNFREEZE
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(payload, (CONTROL_HOST, CONTROL_PORT))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    def send_death_ui() -> None:
        """Tell the server to send 'death' once."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(CONTROL_DEATH, (CONTROL_HOST, CONTROL_PORT))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass


    async def kill_server(e: ft.ControlEvent) -> None:
        nonlocal server_proc
        if server_proc is not None and server_proc.poll() is None:
            try:
                server_proc.terminate()
                server_proc.wait(timeout=5)
            except Exception:
                try:
                    server_proc.kill()
                except Exception:
                    pass
        await page.window.close()



    button_onoff.on_click = change_onoff_text
    button_stop.on_click = toggle_stop_sender_ui
    button_go.on_click = toggle_go_sender_click
    button_death.on_click = lambda e: send_death_ui()
    button_kill.on_click = kill_server
    text_password.on_change = con
    button_conform.on_click = pa
    page.add(
        Row(
            controls=[
                Column(
                    [button_death,
                     button_kill,
                     button_onoff,
                     button_go,
                     button_stop,
                     text_password,
                     button_conform,
                     status_text,
                     ]
                )
            ],
            alignment=ft.MainAxisAlignment.CENTER,
        ))

if __name__ == "__main__":
    ft.run(main)