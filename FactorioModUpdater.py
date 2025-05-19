import os
import re
import requests
import json
import sys
import platform
import traceback
from datetime import datetime
from cryptography.fernet import Fernet
import getpass
import zipfile
import subprocess


# Vérifier si le système d'exploitation est Linux
if platform.system() != "Linux":
    print("Erreur: Ce script est uniquement compatible avec Linux.")
    sys.exit(1)

# Vérifier la présence des modules requests et cryptography
required_packages = ['requests', 'cryptography']

for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        print(f"Le module {package} n'est pas installé. Tentative d'installation avec pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"Le module {package} a été installé avec succès.")
        except subprocess.CalledProcessError:
            print(f"Echec de l'installation de {package} avec pip. Tentative d'installation avec apt...")
            try:
                subprocess.check_call(["sudo", "apt-get", "install", f"python3-{package}"])
                print(f"Le module {package} a été installé avec succés avec apt.")
            except subprocess.CalledProcessError:
                print(f"Echec de l'installation de {package} avec apt.")
                sys.exit(1)

# Chemins et variables statiques
FACTORIO_BINARY_PATH = os.path.join("bin", "x64", "factorio")
LOG_FILE = os.path.expanduser("~/mod_updater.log")
CREDENTIALS_FILE = os.path.expanduser("~/.factorio_credentials")
MODS_DIR = os.path.join(os.getcwd(), "mods")
MOD_LIST_FILE = os.path.join(MODS_DIR, "mod-list.json")
MODS_TO_IGNORE = ["base", "elevated-rails", "quality", "space-age"]

# Fonction pour écrire dans le fichier log
def log_error(message):
    try:
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        log_message = f"{timestamp} - {message}\n"
        with open(LOG_FILE, 'a') as f:
            f.write(log_message)
    except Exception as e:
        print(f"Erreur lors de l'écriture dans le fichier de log: {str(e)}")

# Fonction pour vérifier les permissions de lecture et écriture
def check_permissions(path, mode):
    return os.access(path, mode)

# Fonction pour vérifier si sudo est installé
def is_sudo_installed():
    return os.system("which sudo > /dev/null 2>&1") == 0

# Fonction pour relancer le script avec sudo
def restart_with_sudo():
    os.execvp("sudo", ["sudo", "python3"] + sys.argv)

# Générer une clé de chiffrement
def generate_key():
    return Fernet.generate_key()

# Chiffrer les informations d'identification
def encrypt_credentials(key, credentials):
    fernet = Fernet(key)
    return fernet.encrypt(credentials.encode())

# Déchiffrer les informations d'identification
def decrypt_credentials(key, encrypted_credentials):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_credentials).decode()

# Demander les informations d'identification
def get_credentials():
    username = input("Nom d'utilisateur: ")
    password = getpass.getpass("Mot de passe: ")
    return f"{username}:{password}"

# Enregistrer les informations d'identification chiffrées
def save_credentials(key, encrypted_credentials):
    with open(CREDENTIALS_FILE, 'wb') as f:
        f.write(key + b'\n' + encrypted_credentials)

# Charger les informations d'identification chiffrées
def load_credentials():
    with open(CREDENTIALS_FILE, 'rb') as f:
        key = f.readline().strip()
        encrypted_credentials = f.readline().strip()
    return key, encrypted_credentials

# Obtenir le token d'authentification
def get_auth_token(username, password):
    auth_url = "https://auth.factorio.com/api-login"
    response = requests.post(auth_url, data={"username": username, "password": password})
    
    if response.status_code == 200:
        try:
            # Vérifier si la réponse est un JSON valide
            response_json = response.json()
            if isinstance(response_json, list) and len(response_json) > 0:
                return response_json[0] # Récupérer le token
            else:
                error_message = f"Erreur: Réponse inattendue de l'API: {response_json}"
                print(error_message)
                log_error(error_message)
                return None
        except ValueError:
            error_message = f"Erreur: Réponse non-JSON de l'API: {response.text}"
            print(error_message)
            log_error(error_message)
            return None
    else:
        error_message = f"Erreur lors de l'authentification: {response.status_code} {response.text}"
        print(error_message)
        log_error(error_message)
        return None

# Vérifier si les informations d'identification sont déjà enregistrées
if os.path.exists(CREDENTIALS_FILE):
    key, encrypted_credentials = load_credentials()
    credentials = decrypt_credentials(key, encrypted_credentials)
else:
    credentials = get_credentials()
    key = generate_key()
    encrypted_credentials = encrypt_credentials(key, credentials)
    save_credentials(key, encrypted_credentials)

# Utiliser les information d'identification pour l'authentification
username, password = credentials.split(':')
auth_token = get_auth_token(username, password)

if not auth_token:
    print("Erreur: Impossible d'obtenir le token d'authentification.")
    sys.exit(1)


# Fonction pour télécharger un fichier
def download_file(url, destination, token, username):
    try:
        if not check_permissions(os.path.dirname(destination), os.W_OK):
            error_message = f"Erreur: Permission d'écriture refusée pour {destination}"
            print(error_message)
            log_error(error_message)
            return False

        payload = {'username': username,
                   'token': token,
                   'apiVersion': 2}

        
        response = requests.get(url, params=payload)
        response.raise_for_status()  # Vérifier les erreurs HTTP

        with open(destination, 'wb') as f:
            f.write(response.content)
        
        # Vérification du fichier téléchargé
        if not os.path.exists(destination):
            error_message = f"Erreur: Le fichier {destination} n'a pas été téléchargé."
            print(error_message)
            log_error(error_message)
            return False
        
        # Vérification de la taille du fichier
        if os.path.getsize(destination) == 0:
            error_message = f"Erreur: Le fichier {destination} est vide."
            print(error_message)
            log_error(error_message)
            return False
        
        # Vérification du contenu du fichier ZIP
        try:
            with zipfile.ZipFile(destination, 'r') as zip_ref:
                if zip_ref.testzip() is not None:
                    error_message = f"Erreur: Le fichier {destination} est un fichier ZIP corrompu."
                    print(error_message)
                    log_error(error_message)
                    return False
        except zipfile.BadZipFile:
            error_message = f"Erreur: Le fichier {destination} n'est pas un fichier ZIP valide."
            print(error_message)
            log_error(error_message)
            return False
        
        return True
    except Exception as e:
        error_message = f"Erreur lors du téléchargement de {url}: {str(e)}"
        print(error_message)
        log_error(error_message)
        return False

# Fonction pour obtenir la dernière version d'un mod
def get_latest_mod_version(mod_name, token):
    try:
        api_url = f"https://mods.factorio.com/api/mods/{mod_name}"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(api_url, headers=headers)
        response.raise_for_status() # Vérifier les erreurs HTTP
        if response.status_code == 200:
            mod_info = response.json()
            if "releases" in mod_info and mod_info["releases"]:
                return mod_info["releases"][-1]["version"] # Obtenir la dernière version
            else:
                error_message = f"Erreur: Aucune version trouvée pour {mod_name}"
                print(error_message)
                log_error(error_message)
                return None
        else:
            error_message = f"Erreur: Impossible de récupérer la dernière version pour {mod_name}"
            print(error_message)
            log_error(error_message)
            return None
    except Exception as e:
        error_message = f"Erreur lors de la récupération de la dernière version pour {mod_name}: {str(e)}"
        print(error_message)
        log_error(error_message)
        return None

# Fonction pour extraire le nom du mod et la version du nom du fichier zip
def extract_mod_name_and_version(filename):
    # Pattern pour extraire le nom du mod et la version
    mod_pattern = re.compile(r"^([A-Za-z0-9_-]+)_(\d+\.\d+\.\d+)\.zip$")
    match = mod_pattern.match(filename)
    if match:
        return match.group(1), match.group(2)
    return None, None

# Fonction pour vérifier si un mod est présent dans le dossier mods
def is_mod_present(mod_name):
    mod_zip_pattern = re.compile(r"^([A-Za-z0-9_-]+)_(\d+\.\d+\.\d+)\.zip$")
    for file in os.listdir(MODS_DIR):
        match = mod_zip_pattern.match(file)
        if match and match.group(1) == mod_name:
            return True
    return False

# Fonction pour extraire la version du nom du fichier zip
def get_current_mod_version(mod_name):
    if not check_permissions(MODS_DIR, os.R_OK):
        error_message = f"Erreur: Permission de lecture refusée pour {MODS_DIR}"
        print(error_message)
        log_error(error_message)
        return None
    mod_zip_pattern = re.compile(r"^([A-Za-z0-9_-]+)_(\d+\.\d+\.\d+)\.zip$")
    for file in os.listdir(MODS_DIR):
        match = mod_zip_pattern.match(file)
        if match and match.group(1) == mod_name:
            return match.group(2)
    return None

# Fonction pour supprimer l'ancienne version d'un mod
def delete_old_mod_version(mod_name, current_version):
    old_mod_zip_path = os.path.join(MODS_DIR, f"{mod_name}_{current_version}.zip")
    if os.path.exists(old_mod_zip_path):
        if not check_permissions(MODS_DIR, os.W_OK):
            error_message = f"Erreur: Permission d'écriture refusée pour {MODS_DIR}"
            print(error_message)
            log_error(error_message)
            return False
        os.remove(old_mod_zip_path)
        print(f"Ancienne version de {mod_name} supprimée.")
        return True
    return False

# Fonction pour télécharger un mod
def download_mod(mod_name, mod_version, token, username):
    try:
        # Obtenir l'url de téléchargement via l'API de Factorio
        api_url = f"https://mods.factorio.com/api/mods/{mod_name}"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(api_url, headers=headers)
        response.raise_for_status() # Vérifier les erreurs HTTP
        if response.status_code == 200:
            mod_info = response.json()
            # Trouver la version spécifique dans les releases
            for release in mod_info["releases"]:
                if release["version"] == mod_version:
                    download_url = release["download_url"]
                    break
            else:
                error_message = f"Erreur: Version {mod_version} non trouvée pour {mod_name}"
                print(error_message)
                log_error(error_message)
                return None
            
            # On s'assure que l'URL de téléchargement est correctement formatée
            if not download_url.startswith("https://mods.factorio.com/"):
                download_url = f"https://mods.factorio.com{download_url}"
            
            mod_zip_path = os.path.join(MODS_DIR, f"{mod_name}_{mod_version}.zip")

            print(f"Téléchargement de {mod_name} version {mod_version}...")
            try:
                if download_file(download_url, mod_zip_path, token, username):
                    return mod_zip_path
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    error_message = f"Erreur 403: Accés interdit pour {download_url}. Vérifiez les permissions ou l'authentification."
                    print(error_message)
                    log_error(error_message)
                else:
                    error_message = f"Erreur lors du téléchargement de {mod_name}: {str(e)}"
                    print(error_message)
                    log_error(error_message)
            return None
        else:
            error_message = f"Erreur: Impossible de récupérer l'URL de téléchargement pour {mod_name}"
            print(error_message)
            log_error(error_message)
            return None
    except Exception as e:
        error_message = f"Erreur lors du téléchargement de {mod_name}: {str(e)}"
        print(error_message)
        log_error(error_message)
        return None

# Fonction pour vérifier et mettre à jour les mods
def check_and_update_mods(token, username):
    if not os.path.exists(MODS_DIR) or not os.path.exists(MOD_LIST_FILE):
        print("Aucun mod n'est installé.")
        return
    
    if not check_permissions(MOD_LIST_FILE, os.R_OK):
        error_message = f"Erreur: Permission de lecture refusée pour {MOD_LIST_FILE}"
        print(error_message)
        log_error(error_message)
        return
    
    with open(MOD_LIST_FILE, 'r') as f:
        mods_data = json.load(f)
    
    if "mods" not in mods_data or not mods_data["mods"]:
        print("Aucun mod n'est installée.")
        return
    
    for mod in mods_data["mods"]:
        if isinstance(mod, dict) and "name" in mod:
            mod_name = mod["name"]

            # Ignorer les mods spécifiques
            if mod_name in MODS_TO_IGNORE:
                print(f"Ignorer le mod {mod_name}")
                continue

            latest_version = get_latest_mod_version(mod_name, token)

            if not is_mod_present(mod_name):
                print(f"Le mod {mod_name} n'est pas présent. Téléchargement de la dernière version...")
                download_mod(mod_name, latest_version, token, username)
            else:
                current_version = get_current_mod_version(mod_name)
                if latest_version and latest_version != current_version:
                    new_mod_zip_path = download_mod(mod_name, latest_version, token)
                    if new_mod_zip_path and current_version:
                        delete_old_mod_version(mod_name, current_version)
                else:
                    print(f"Le mod {mod_name} est déjà à jour ou impossible de trouver la dernière version.")
        else:
            error_message = f"Elément invalide dans mod-list.json: {mod}"
            print(error_message)
            log_error(error_message)
    
    print("Mise à jour des mods terminée.")

# Vérifier si le script est lancé à la racine du répertoire de Factorio
if not os.path.exists(FACTORIO_BINARY_PATH):
    error_message = "Erreur: Le script doit être exécuté depuis la racine du répertoire de Factorio."
    print(error_message)
    log_error(error_message)
    sys.exit(1)

# Vérifier les permissions
if not check_permissions(MODS_DIR, os.R_OK | os.W_OK) or not check_permissions(MOD_LIST_FILE, os.R_OK):
    if is_sudo_installed():
        print("Redémarrage du script avec sudo...")
        restart_with_sudo()
    else:
        error_message = "Erreur: Le paquet sudo n'est pas installé. Veuillez installer sudo et relancer le script en mode superutilisateur."
        print(error_message)
        log_error(error_message)
        sys.exit(1)
else:
    check_and_update_mods(auth_token, username)