Documentation pour le Script de Mise à Jour des Mods Factorio
Description

Ce script Python est conçu pour automatiser la mise à jour des mods pour le serveur headless Factorio sous Linux. Il vérifie les versions des mods installés, télécharge les dernières versions disponibles, et remplace les anciennes versions par les nouvelles.
Prérequis

    Système d'exploitation : Linux
    Python : Python 3.x
    Modules Python : requests, cryptography
    Permissions : Le script doit être exécuté avec les permissions appropriées pour lire et écrire dans le répertoire des mods de Factorio.

Installation

    Cloner le dépôt :

    git clone https://github.com/foley64/FactorioModUpdater.git
    cd FactorioModUpdater

    Installer les dépendances :
        Le script vérifie et installe automatiquement les modules requests et cryptography au démarrage. Assurez-vous d'avoir pip et apt configurés correctement.

    Configurer les informations d'identification :
        Le script demandera vos informations d'identification (nom d'utilisateur et mot de passe) pour se connecter à l'API de Factorio. Ces informations sont stockées de manière sécurisée.

Utilisation

    Exécuter le script :
        Assurez-vous d'être dans le répertoire racine de Factorio.
        Exécutez le script avec Python :

        python3 FactorioModUpdater.py

    Journalisation :
        Le script enregistre les erreurs et les actions dans un fichier de log situé à ~/mod_updater.log.

Configuration

    Répertoire des Mods : Le script suppose que le répertoire des mods est situé dans ./mods par rapport au répertoire d'exécution.
    Fichier de Liste des Mods : Le script utilise mod-list.json pour obtenir la liste des mods installés.
