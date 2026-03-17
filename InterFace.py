import sys
import subprocess
import socket
import time
import atexit
import flet as ft
from flet import Row, Column, Text, TextField

def send_udp_command_to_server(command_payload: bytes, host: str, port: int) -> None:
    try:
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        control_socket.sendto(command_payload, (host, port))
    except Exception:
        pass
    finally:
        try:
            control_socket.close()
        except Exception:
            pass


def main(page: ft.Page) -> None:
    page.title = "control"
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 40
    page.window_height = 50
    page.window_resizable = False

    button_death = ft.Button(content=ft.Text("death"), width=200)
    button_kill = ft.Button(content=ft.Text("kill"), width=200)
    button_stop_video = ft.Button(content=ft.Text("stop"), width=200, disabled=True)
    button_resume_video = ft.Button(content=ft.Text("go"), width=200, disabled=False)
    button_toggle_freeze = ft.Button(content=ft.Text("freeze"), width=200)
    input_password = TextField(label="Password", width=200)
    button_confirm_password = ft.Button(content=ft.Text("confirm"), width=200, disabled=True)
    status_text = Text(value="Server: not running")

    current_password = ""
    server_process = None
    is_managed_mode = "--managed" in sys.argv

    def cleanup_background_server():
        if server_process is not None and server_process.poll() is None:
            try:
                server_process.terminate()
            except Exception:
                pass

    atexit.register(cleanup_background_server)

    CONTROL_HOST = "127.0.0.1"
    CONTROL_PORT = 50099
    CONTROL_TOGGLE_STOP = b"toggle_stop_sender"
    CONTROL_TOGGLE_GO = b"toggle_go_sender"
    CONTROL_FREEZE = b"freeze_ten_times"
    CONTROL_UNFREEZE = b"unfreeze_ten_times"
    CONTROL_DEATH = b"death_message"
    CONTROL_SET_PASSWORD_PREFIX = b"set_password:"

    def on_password_input_change(event: ft.ControlEvent) -> None:
        print(f"Password changed: {input_password.value}")
        if input_password.value and input_password.value.strip():
            button_confirm_password.disabled = False
        else:
            button_confirm_password.disabled = True
        page.update()

    def on_toggle_freeze_click(event: ft.ControlEvent):
        print("Toggle freeze clicked.")
        if isinstance(event.control.content, ft.Text):
            is_currently_frozen = event.control.content.value == "unfreeze"
            
            if not is_currently_frozen:
                send_udp_command_to_server(CONTROL_FREEZE, CONTROL_HOST, CONTROL_PORT)
                event.control.content.value = "unfreeze"
            else:
                send_udp_command_to_server(CONTROL_UNFREEZE, CONTROL_HOST, CONTROL_PORT)
                event.control.content.value = "freeze"
        page.update()

    def _send_password_to_server_with_retries(password: str) -> None:
        print(f"Sending password to server: {password}")
        try:
            password_bytes = (password or "").encode("utf-8")
        except Exception:
            password_bytes = b""

        payload = CONTROL_SET_PASSWORD_PREFIX + password_bytes

        for _ in range(10):
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_socket.sendto(payload, (CONTROL_HOST, CONTROL_PORT))
                test_socket.close()
                break
            except Exception:
                time.sleep(0.1)

    def on_confirm_password_click(event: ft.ControlEvent) -> None:
        print("Confirm password clicked.")
        nonlocal current_password, server_process
        current_password = input_password.value

        if is_managed_mode:
            status_text.value = "Server: running (managed)"
            _send_password_to_server_with_retries(current_password)
            page.update()
            return

        if server_process is not None and server_process.poll() is None:
            status_text.value = "Server: already running"
            page.update()
            return

        try:
            server_process = subprocess.Popen([sys.executable, "server.py", "--no-ui"])
            status_text.value = "Server: running"
            _send_password_to_server_with_retries(current_password)
        except Exception as error_details:
            status_text.value = f"Server failed: {error_details}"

        page.update()

    def on_stop_video_click(event: ft.ControlEvent) -> None:
        print("Stop video clicked.")
        send_udp_command_to_server(CONTROL_TOGGLE_STOP, CONTROL_HOST, CONTROL_PORT)
        button_resume_video.disabled = False
        button_stop_video.disabled = True
        page.update()

    def on_resume_video_click(event: ft.ControlEvent) -> None:
        print("Resume video clicked.")
        send_udp_command_to_server(CONTROL_TOGGLE_GO, CONTROL_HOST, CONTROL_PORT)
        button_stop_video.disabled = False
        button_resume_video.disabled = True
        page.update()

    def send_shutdown_command_to_server() -> None:
        print("Sending shutdown command to server.")
        send_udp_command_to_server(CONTROL_DEATH, CONTROL_HOST, CONTROL_PORT)

    async def on_kill_server_click(event: ft.ControlEvent) -> None:
        nonlocal server_process
        if server_process is not None and server_process.poll() is None:
            try:
                server_process.terminate()
                server_process.wait(timeout=5)
            except Exception:
                try:
                    server_process.kill()
                except Exception:
                    pass
        await page.window.close()

    button_toggle_freeze.on_click = on_toggle_freeze_click
    button_stop_video.on_click = on_stop_video_click
    button_resume_video.on_click = on_resume_video_click
    button_death.on_click = lambda e: send_shutdown_command_to_server()
    button_kill.on_click = on_kill_server_click
    input_password.on_change = on_password_input_change
    button_confirm_password.on_click = on_confirm_password_click

    page.add(
        Row(
            controls=[
                Column([
                    button_death,
                    button_kill,
                    button_toggle_freeze,
                    button_resume_video,
                    button_stop_video,
                    input_password,
                    button_confirm_password,
                    status_text,
                ])
            ],
            alignment=ft.MainAxisAlignment.CENTER,
        )
    )

if __name__ == "__main__":
    ft.run(main)
