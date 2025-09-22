import threading
from honey.ssh_honeypot import server_ssh_loop
from honey.telnet_honeypot import server_telnet_loop
from honey.http_honeypot import run_http_server
from honey.ftp_honeypot import server_ftp_loop
from honey.honey_port import main_honeyport

if __name__ == "__main__":
    t1 = threading.Thread(target=server_ssh_loop, daemon=True)
    t2 = threading.Thread(target=server_telnet_loop, daemon=True)
    t3 = threading.Thread(target=run_http_server, daemon=True)
    t4 = threading.Thread(target=server_ftp_loop, daemon=True)
    t5 = threading.Thread(target=main_honeyport, daemon=True)
    

    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    # 主线程保持运行，否则程序会直接退出
    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()
