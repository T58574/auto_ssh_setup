import os
import subprocess
import paramiko
import argparse

def ensure_ssh_key_exists(
    private_key_path="~/.ssh/id_rsa",
    public_key_path="~/.ssh/id_rsa.pub"
):
    """
    Проверяем, есть ли SSH-ключи. Если нет — генерируем новую пару (RSA 4096).
    Возвращаем путь к публичному ключу.
    """
    private_key_path = os.path.expanduser(private_key_path)
    public_key_path = os.path.expanduser(public_key_path)

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("[INFO] SSH-ключи не найдены. Генерируем новую пару...")
        subprocess.run([
            "ssh-keygen",
            "-t", "rsa",
            "-b", "4096",
            "-f", private_key_path,
            "-N", ""
        ], check=True)
        print("[INFO] Ключи сгенерированы.")

    return public_key_path

def add_ssh_key_to_server(host, username, password, public_key_path="~/.ssh/id_rsa.pub"):
    """
    Подключаемся к удалённому серверу по паролю и добавляем локальный
    публичный ключ в ~/.ssh/authorized_keys.
    """
    public_key_path = os.path.expanduser(public_key_path)

    # Считываем публичный ключ локально
    with open(public_key_path, "r") as f:
        pub_key = f.read().strip()

    # Подключаемся к серверу при помощи Paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    print(f"[INFO] Подключаемся к {host} по SSH (логин: {username}).")
    ssh.connect(hostname=host, username=username, password=password)

    # Создаём каталог ~/.ssh (если не существует) и выставляем права 700
    commands = [
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
        # Добавляем публичный ключ в authorized_keys
        f'echo "{pub_key}" >> ~/.ssh/authorized_keys',
        # Выставляем нужные права
        "chmod 600 ~/.ssh/authorized_keys"
    ]

    for cmd in commands:
        ssh.exec_command(cmd)

    # Закрываем соединение
    ssh.close()
    print("[INFO] Публичный ключ успешно добавлен на сервер. Теперь можно подключаться без пароля.")

def main():
    parser = argparse.ArgumentParser(
        description="Скрипт для автоматического добавления SSH-ключа на удалённый сервер (Ubuntu)."
    )
    parser.add_argument(
        "--host",
        required=True,
        help="IP-адрес или домен сервера (например, 192.168.0.10)"
    )
    parser.add_argument(
        "--user",
        required=True,
        help="Имя пользователя на сервере (например, ubuntu)"
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Пароль от указанного пользователя (для первичного входа)"
    )

    args = parser.parse_args()

    # 1. Проверяем/генерируем локальный SSH-ключ
    pub_key_path = ensure_ssh_key_exists()

    # 2. Добавляем этот ключ на сервер
    add_ssh_key_to_server(
        host=args.host,
        username=args.user,
        password=args.password,
        public_key_path=pub_key_path
    )

    print("\n[INFO] Попробуйте подключиться к серверу без пароля командой:")
    print(f"ssh {args.user}@{args.host}")

if __name__ == "__main__":
    main()