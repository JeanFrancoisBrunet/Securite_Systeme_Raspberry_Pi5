# Protection PI5 — Console de sécurité système

Console de sécurité Tkinter centralisant, pour un Raspberry Pi 5, le pilotage des principaux outils de protection : antivirus, anti-intrusion, pare-feu, surveillance réseau, VPN, audit de sécurité et monitoring système. Chaque outil dispose de son propre onglet, avec actions guidées et console de sortie dédiée.

## Onglets

### 🦠 Anti-Virus — ClamAV
- Analyse d'un dossier (par défaut le répertoire personnel de l'utilisateur), récursive ou non.
- **Comptage préliminaire** des fichiers/dossiers avant analyse, puis suivi en **temps réel** : fichiers scannés, vitesse, temps restant estimé (ETA).
- Analyse **annulable** en cours d'exécution.

### 🛡 Anti-Intrusion — Fail2Ban
- Démarrage / arrêt du service, avec **création automatique** de `/etc/fail2ban/jail.local` si absent (jail `sshd`, backend `systemd` adapté à Raspberry Pi OS Bullseye/Bookworm).
- Consultation du statut de la jail `sshd` : résumé du nombre d'IP actuellement bannies, avec détail complet en dessous.
- Vérification rapide de l'état du service (actif/inactif).
- **Débannissement d'IP** via une boîte de dialogue proposant directement la liste des IP bannies.

### 🔥 Pare-Feu — UFW
- Gestion du pare-feu UFW (activation, règles, statut) depuis un onglet dédié, avec résumé (actif/inactif, nombre de règles) suivi du détail complet.

### 📡 Surveillance Réseau — WireShark
- **Capture réseau** de 10 secondes sur l'interface active (détectée automatiquement via `ip route`), avec un résumé (nombre de connexions détectées) suivi du détail complet des conversations IP (`tshark -z conv,ip`).
- **Découverte des appareils connectés** sur le réseau local (`arp-scan`, ou repli sur `arp -a` si absent), avec décompte du nombre d'appareils détectés.
- **Détection d'intrusions basique** : connexions établies, ports en écoute, 20 derniers événements du service SSH.
- Lancement de l'interface graphique **Wireshark** en tant qu'utilisateur normal (avertissement contre l'exécution en root).

### 🔒 VPN — WireGuard
- Génération des clés, création du fichier `wg0.conf`.
- Démarrage / arrêt de l'interface `wg0`, consultation du statut.
- Activation / désactivation du **démarrage automatique** au reboot.
- Rappel : réserver une IP fixe pour chaque client sur la box/routeur.

### 🕵️ Audit Sécurité — Hydra & Nmap
- **Hydra** : test de robustesse SSH par force brute contrôlée (cible, utilisateur, liste de mots de passe, nombre de tâches parallèles), avec avertissement explicite sur l'usage légal (systèmes personnels uniquement).
  - Si un mot de passe est trouvé, il est automatiquement **évalué par `cracklib-check`** (qualité : acceptable / faible / mot du dictionnaire / trivial), avec le mot de passe masqué dans la console (uniquement sa longueur affichée).
- **Nmap** : scan de ports en 3 modes — rapide (`-F`), complet (`-p 1-65535`), détection de services (`-sV`).

### 🔑 Audit Mot de Passe — Cracklib
- Évaluation de la force d'un mot de passe saisi, en direct (`cracklib-check`).
- Analyse d'une **liste de mots de passe** (wordlist) avec suivi de progression et détail des mots faibles détectés (limité à un nombre configurable de lignes affichées).

### 📊 Monitoring Système — Htop et autres
- Tableau de bord temps réel (rafraîchi toutes les 2 secondes) : CPU, RAM, **température** (seuils orange/rouge configurables), uptime, charge système (load average 1/5/15 min).
- **Top 10 processus** par consommation CPU.
- Informations système (`uname`, `lsb_release`, `hostnamectl`, `lscpu`, `free`), disque (`df`, `lsblk`) et réseau (`ip addr`).
- **Analyse d'espace disque** façon `ncdu` : classement des dossiers les plus volumineux (`du -x`, profondeur et nombre de résultats configurables), limité au système de fichiers courant. Rappel intégré vers `sudo ncdu -x /` pour une exploration interactive complète.
- **Nettoyage système** avec sélection des éléments à traiter (cases à cocher) :
  - Paquets APT obsolètes (`autoremove --purge`, `autoclean`, `clean`)
  - Fichiers temporaires (`/tmp`, `/var/tmp`)
  - Journaux systemd, avec durée de rétention réglable (`journalctl --vacuum-time`)
  - Cache pip (`~/.cache/pip`)
  - Cache miniatures (`~/.cache/thumbnails`)
  - Docker : images/conteneurs/volumes inutilisés (`docker system prune`), case affichée uniquement si Docker est installé
  - Un **aperçu** (`apt-get --dry-run autoremove` + `journalctl --disk-usage`) est affiché avant toute confirmation.
  - À l'issue du nettoyage, un **bilan d'espace disque libéré** (avant/après, en Mo/Go) est affiché en plus du détail de chaque commande.

## Fonctionnalités transverses
- Chaque onglet dispose de sa propre console de sortie (horodatée, ✅/❌ selon succès), avec boutons **Effacer** et **Copier tout**.
- Confirmations systématiques avant toute action sensible (démarrage/arrêt de service, nettoyage système, test Hydra…).
- Commandes privilégiées exécutées via `sudo` de façon centralisée.
- Écran de démarrage (splash screen).

## Lancement
```bash
python3 protection_PI5.py
```

## Dépendances
Outils système (à installer selon les onglets utilisés) :
```bash
sudo apt install clamav fail2ban ufw wireshark tshark arp-scan wireguard hydra nmap libcrack2 -y
sudo usermod -aG wireshark $USER
```

Python :
```bash
pip install pillow psutil --break-system-packages
```

> `psutil` est requis pour l'onglet Monitoring — sans lui, l'onglet affiche une invite d'installation et se désactive.

> `ncdu` est optionnel : l'onglet Monitoring y fait référence comme complément pour l'exploration interactive de l'espace disque, mais n'en dépend pas (`sudo apt install ncdu`).

## ⚠️ Avertissement
Les onglets **Hydra** et **Nmap** intègrent des outils d'audit de sécurité offensifs. Leur usage n'est légal que sur des systèmes dont on est propriétaire ou pour lesquels on dispose d'une autorisation explicite. L'application affiche cet avertissement directement dans l'onglet Audit.

## Structure du dépôt
```
Protection_PI5/
├── protection_PI5.py     # Application principale (Tkinter, tous les onglets)
└── icons/                # Logos et images d'illustration par onglet (non inclus ici)
```

## Prérequis
- Raspberry Pi OS (Bullseye/Bookworm) ou toute distribution Linux basée sur Debian
- Droits `sudo` pour la plupart des actions (services systemd, pare-feu, capture réseau, nettoyage système)
- `python3-tk`

## Auteur
Jean-François BRUNET - JFBConseils - Juillet/Septembre 2026
