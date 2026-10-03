#!/usr/bin/env python3
# =============================================================================
#  Protection Système du Raspberry Pi5
#  version intégrant :
#           Anti-Virus - ClamAV
#           Anti-Intrusion - Fail2Ban
#           Pare-Feu - UFW
#           Surveillance Réseau - WireShark
#           VPN - WireGuard
#           Audit Sécurité - Hydra & Nmap
#           Audit Mots de Passe - Cracklib
#           Monitoring Système - Htop et autres...
#
#  Auteur  : Jean‑François BRUNET - JFBConseils - Avril 2026
# =============================================================================

import os
import re
import time
import shutil
import threading
import subprocess
from datetime import datetime
from pathlib import Path

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk

# =============================================================================
#  PARAMÈTRES — pouvant être modifiés
# =============================================================================

# ---- Chemins ----------------------------------------------------------------
BASE_DIR        = Path(__file__).parent          # dossier du script
ICON_DIR        = BASE_DIR / "icons"             # sous-dossier icons/ à côté du script
CLAMAV_SCAN_PATH = Path.home()                   # répertoire home de l'utilisateur courant

# ---- Interface --------------------------------------------------------------
SPLASH_DURATION_MS  = 1500    		# durée du splash screen en millisecondes
SPLASH_IMAGE_NAME   = "FireWall.png"
WINDOW_PADDING      = 40      		# marge ajoutée autour de la fenêtre principale
ICON_SIZE_DEFAULT   = (120, 120)  	# taille par défaut des icônes d'onglet (px)

# ---- Monitoring -------------------------------------------------------------
MONITORING_INTERVAL_MS = 2000   # intervalle de rafraîchissement monitoring (ms)
MONITORING_TOP_N       = 10     # nombre de processus affichés dans le top

# ---- Analyse d'espace disque (façon ncdu) ------------------------------------
DISK_ANALYZE_ROOT     = "/"     # point de départ de l'analyse
DISK_ANALYZE_DEPTH    = 3       # profondeur de parcours (du -d)
DISK_ANALYZE_TOP_N    = 25      # nombre de dossiers affichés dans le classement
DISK_ANALYZE_EXCLUDE  = ["/proc", "/sys", "/dev", "/run", "/mnt", "/media"]

# ---- Nettoyage système : journaux -------------------------------------------
JOURNALCTL_VACUUM_DEFAULT = "7d"   # ancienneté conservée par défaut pour les logs systemd

# ---- Température (°C) -------------------------------------------------------
TEMP_WARN_THRESHOLD = 65   # seuil orange
TEMP_CRIT_THRESHOLD = 75   # seuil rouge

# ---- ClamAV -----------------------------------------------------------------
CLAM_ETA_MIN_PCT   = 0.05   # pourcentage minimum avant affichage de l'ETA (5 %)
CLAM_CURRENT_MAX   = 80     # longueur max du nom de fichier affiché "En cours"

# ---- Audit Hydra ------------------------------------------------------------
HYDRA_DEFAULT_TARGET   = "127.0.0.1"
HYDRA_DEFAULT_USER     = "jfbrunet"
HYDRA_DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
HYDRA_DEFAULT_TASKS    = "4"

# ---- Audit mot de passe -----------------------------------------------------
PASSWD_DEFAULT_WORDLIST   = "/usr/share/wordlists/rockyou.txt"
PASSWD_DEFAULT_LIMIT      = "100"
PASSWD_WL_DISPLAY_MAX     = 200   # max de lignes faibles affichées après analyse

# ---- WireGuard --------------------------------------------------------------
WG_DEFAULT_VPN_IP  = "10.221.90.1/24"
WG_DEFAULT_PORT    = "51820"

# ---- Séparateur console -----------------------------------------------------
CONSOLE_SEP = "─" * 62

# =============================================================================
#  Splash Screen
# =============================================================================
class SplashScreen:
    def __init__(self, root, image_path):
        self.root   = root
        self.splash = tk.Toplevel(root)
        self.splash.overrideredirect(True)

        try:
            img = Image.open(image_path)
            img.thumbnail((500, 500), Image.LANCZOS)
            self.photo = ImageTk.PhotoImage(img)
            tk.Label(self.splash, image=self.photo, bg="white").pack()
        except Exception as e:
            tk.Label(self.splash, text=f"Chargement...\n{e}").pack(padx=20, pady=20)

        self.splash.update_idletasks()
        w = self.splash.winfo_width()
        h = self.splash.winfo_height()
        x = (self.root.winfo_screenwidth()  - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.splash.geometry(f"{w}x{h}+{x}+{y}")

    def close(self):
        if self.splash.winfo_exists():
            self.splash.destroy()

# =============================================================================
#  Contrôleur ClamAV (thread, annulable, streaming temps réel)
# =============================================================================
class ClamAVController:
    def __init__(self, on_result, on_progress=None, on_pre_count=None):
        self.on_result    = on_result		# appelé en fin de scan avec le résultat complet
        self.on_progress  = on_progress		# appelé pour chaque fichier scanné
        self.on_pre_count = on_pre_count	# appelé après le comptage préliminaire
        self._process     = None

    # ------------------------------------------------------------------
    def scan_async(self, path, options):
        t = threading.Thread(target=self._run, args=(path, options), daemon=True)
        t.start()

    def stop(self):
        """Interrompt le processus clamscan en cours."""
        if self._process and self._process.poll() is None:
            self._process.terminate()

    # ------------------------------------------------------------------
    def _count_targets(self, path, recursive):
        """Compte les fichiers et répertoires à analyser."""
        nb_files = nb_dirs = 0
        if recursive:
            for root_dir, dirs, files in os.walk(path):
                nb_dirs  += len(dirs)
                nb_files += len(files)
        else:
            try:
                for entry in os.scandir(path):  
                    if entry.is_file():
                        nb_files += 1
                    elif entry.is_dir():
                        nb_dirs += 1
            except OSError:
                pass
        return nb_files, nb_dirs

    # ------------------------------------------------------------------
    def _run(self, path, options):
        recursive = "-r" in options

        # ① Comptage préliminaire
        nb_files, nb_dirs = self._count_targets(path, recursive)
        if self.on_pre_count:
            self.on_pre_count(nb_files, nb_dirs)

        # ② Lancement clamscan
        cmd          = ["clamscan"] + options + [path]
        output_lines = []
        scanned      = 0
        t_start      = time.monotonic()

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for raw_line in self._process.stdout:
                line = raw_line.rstrip("\n")
                output_lines.append(line)

                if line.startswith("/") and ": " in line and not line.startswith("/-"):
                    scanned += 1
                    elapsed  = time.monotonic() - t_start
                    speed    = scanned / elapsed if elapsed > 0 else 0
                    pct_done = scanned / nb_files if nb_files > 0 else 0
                    if pct_done >= CLAM_ETA_MIN_PCT and speed > 0:
                        eta_sec = (nb_files - scanned) / speed
                    else:
                        eta_sec = None
                    if self.on_progress:
                        self.on_progress(scanned, nb_files, eta_sec, speed, line)

            self._process.wait()
            if self._process.returncode == -15:
                output_lines.append("\nScan interrompu par l'utilisateur.\n")
        except Exception as e:
            output_lines.append(f"Erreur lors du scan ClamAV : {e}")
        finally:
            self._process = None

        self.on_result("\n".join(output_lines))

# =============================================================================
#  Application principale
# =============================================================================
class SecurityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Sécurité Raspberry Pi 5")

        self._build_style()
        self._build_notebook()

        # Centrage + taille automatique
        self.root.update_idletasks()
        req_w = self.root.winfo_reqwidth()  + WINDOW_PADDING
        req_h = self.root.winfo_reqheight() + WINDOW_PADDING
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x  = (sw - req_w) // 2
        y  = (sh - req_h) // 2
        self.root.geometry(f"{req_w}x{req_h}+{x}+{y}")
        self.root.minsize(req_w, req_h)

    # =========================================================================
    #  Style
    # =========================================================================
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Success.TButton", foreground="black",  background="#00cc44")
        style.map("Success.TButton",        background=[("active", "#00ff55")])
        style.configure("Danger.TButton",  foreground="white",  background="#cc0000")
        style.map("Danger.TButton",         background=[("active", "#ff0000")])
        style.configure("Info.TButton",    foreground="white",  background="#0066cc")
        style.map("Info.TButton",           background=[("active", "#0088ff")])

    # =========================================================================
    #  Helper : chargement d'icône
    # =========================================================================
    def _load_icon(self, filename, size=ICON_SIZE_DEFAULT):
        """Charge et redimensionne une icône depuis ICON_DIR. Retourne None si absent."""
        path = ICON_DIR / filename
        if not path.exists():
            return None
        try:
            img = Image.open(path)
            img.thumbnail(size, Image.LANCZOS)
            return ImageTk.PhotoImage(img)
        except Exception:
            return None

    # =========================================================================
    #  Helper : exécution sudo
    # =========================================================================
    def _run_sudo(self, cmd_list):
        """Exécute une commande avec sudo. Retourne (stdout_str, success_bool)."""
        try:
            result = subprocess.run(
                ["sudo"] + cmd_list,
                capture_output=True, text=True
            )
            output = result.stdout + result.stderr
            return output, result.returncode == 0
        except Exception as e:
            return f"Erreur : {e}", False

    # =========================================================================
    #  Helper générique : copier tout dans le presse-papiers
    # =========================================================================
    def _copy_text_widget(self, text_widget):
        """Copie le contenu d'un ScrolledText dans le presse-papiers."""
        content = text_widget.get(1.0, tk.END)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            self.root.update()
            if self.root.clipboard_get().strip():
                messagebox.showinfo("...", "  Copié dans \nPresse-papiers.")
                return
        except Exception:
            pass
        for tool, args in [
            ("xclip", ["-selection", "clipboard"]),
            ("xsel",  ["--clipboard", "--input"]),
        ]:
            try:
                proc = subprocess.Popen([tool] + args, stdin=subprocess.PIPE, text=True)
                proc.communicate(input=content)
                if proc.returncode == 0:
                    messagebox.showinfo("Copié", f"  Copié dans \nPresse-papiers \n(via {tool}).")
                    return
            except FileNotFoundError:
                continue
        messagebox.showwarning(
            "Copie impossible",
            "Impossible de copier automatiquement.\n"
            "Installez xclip :  sudo apt install xclip"
        )

    # =========================================================================
    #  Helper : tooltip
    # =========================================================================
    def _add_tooltip(self, widget, text):
        tip_win = []
        def enter(e):
            x = widget.winfo_rootx() + 20
            y = widget.winfo_rooty() + widget.winfo_height() + 4
            w = tk.Toplevel(widget)
            w.overrideredirect(True)
            w.geometry(f"+{x}+{y}")
            tk.Label(w, text=text, background="#ffffe0", relief="solid",
                     borderwidth=1, font=("TkDefaultFont", 8), justify="left").pack()
            tip_win.append(w)
        def leave(e):
            for w in tip_win:
                w.destroy()
            tip_win.clear()
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    # =========================================================================
    #  Notebook
    # =========================================================================
    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill="both", padx=8, pady=8)

        tabs = [
            ("Anti-Virus - ClamAV",            self._build_tab_clamav),
            ("Anti-Intrusion - Fail2Ban",       self._build_tab_fail2ban),
            ("Pare-Feu - UFW",                  self._build_tab_ufw),
            ("Surveillance Réseau - WireShark", self._build_tab_wireshark),
            ("VPN - WireGuard",                 self._build_tab_wireguard),
            ("Audit Sécurité - Hydra & Nmap",   self._build_tab_audit),
            ("Audit Mot de Passe",              self._build_tab_passwd),
            ("Monitoring Système - Htop",       self._build_tab_monitoring),
        ]
        for label, builder in tabs:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=label)
            builder(frame)

    # =========================================================================
    #  Onglet ClamAV
    # =========================================================================
    def _build_tab_clamav(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        # ---- Ligne 0 : icône + titre + boutons ----
        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))

        self.img_clamav = self._load_icon("ClamAV.png", (150, 150))
        if self.img_clamav:
            ttk.Label(frame_top, image=self.img_clamav).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top, text="ClamAV – Analyse AntiVirus",
            font=("TkDefaultFont", 12, "bold"), justify="left"
        ).pack(side="left", padx=5)

        self.btn_clam_stop = ttk.Button(
            frame_top, text="⏹ Arrêter le scan",
            command=self._stop_clamav_scan, style="Danger.TButton"
        )
        self.btn_clam_scan = ttk.Button(
            frame_top, text="▶ Lancer le scan",
            command=self._start_clamav_scan, style="Success.TButton"
        )
        self.btn_clam_scan.pack(side="right", padx=5)
        ttk.Button(
            frame_top, text="🔍 Mettre à jour la base virale",
            command=self._update_clamav_db, style="Info.TButton"
        ).pack(side="right", padx=5)

        # ---- Ligne 1 : options de scan ----
        frame_opts = ttk.LabelFrame(tab, text="Options de scan")
        frame_opts.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        frame_opts.columnconfigure(1, weight=1)

        ttk.Label(frame_opts, text="Dossier à scanner :").grid(
            row=0, column=0, sticky="w", padx=8, pady=4)
        self.scan_path_var = tk.StringVar(value=str(CLAMAV_SCAN_PATH))
        ttk.Entry(frame_opts, textvariable=self.scan_path_var, width=40).grid(
            row=0, column=1, sticky="ew", padx=4, pady=4)
        ttk.Button(
            frame_opts, text="▶ Parcourir", command=self._browse_scan_path
        ).grid(row=0, column=2, padx=6, pady=4)

        self.recursive_var = tk.BooleanVar(value=True)
        cb_rec = ttk.Checkbutton(
            frame_opts, text="Récursif (sous-dossiers inclus)",
            variable=self.recursive_var
        )
        cb_rec.grid(row=0, column=3, padx=12, pady=4, sticky="w")
        self._add_tooltip(cb_rec,
            "Coché : parcourt tous les sous-dossiers.\n"
            "Décoché : analyse uniquement les fichiers à la racine du dossier choisi.")

        ttk.Label(frame_opts, text="Mode de scan :").grid(
            row=1, column=0, sticky="w", padx=8, pady=4)
        self.scan_mode_var = tk.StringVar(value="standard")
        mode_frame = ttk.Frame(frame_opts)
        mode_frame.grid(row=1, column=1, columnspan=3, sticky="w", padx=4)
        modes = [
            ("Standard  ★", "standard",
             "Fichiers ≤ 25 Mo — archives exclues.\nRapide et suffisant pour un usage quotidien."),
            ("Complet",     "complet",
             "Fichiers ≤ 500 Mo — archives ZIP/RAR/PDF incluses.\n"
             "Plus lent mais exhaustif (conseillé une fois par semaine)."),
        ]
        for label, val, tip in modes:
            rb = ttk.Radiobutton(mode_frame, text=label, value=val, variable=self.scan_mode_var)
            rb.pack(side="left", padx=12)
            self._add_tooltip(rb, tip)

        ttk.Label(frame_opts, text="Sortie :").grid(
            row=2, column=0, sticky="w", padx=8, pady=4)
        self.verbose_var       = tk.BooleanVar(value=False)
        self.show_ok_var       = tk.BooleanVar(value=False)
        self.infected_only_var = tk.BooleanVar(value=False)
        verb_frame = ttk.Frame(frame_opts)
        verb_frame.grid(row=2, column=1, columnspan=3, sticky="w", padx=4)
        cb_v = ttk.Checkbutton(verb_frame, text="Verbose",
                                variable=self.verbose_var, command=self._sync_verbose)
        cb_v.pack(side="left", padx=8)
        self._add_tooltip(cb_v, "Affiche chaque fichier analysé (--verbose).\nSortie très longue.")
        cb_ok = ttk.Checkbutton(verb_frame, text="Afficher fichiers sains",
                                 variable=self.show_ok_var, command=self._sync_verbose)
        cb_ok.pack(side="left", padx=8)
        self._add_tooltip(cb_ok,
            "Inclut les lignes « : OK » dans la sortie.\n"
            "Par défaut elles sont masquées pour alléger l'affichage.")
        cb_inf = ttk.Checkbutton(verb_frame, text="Infectés seulement",
                                  variable=self.infected_only_var, command=self._sync_verbose)
        cb_inf.pack(side="left", padx=8)
        self._add_tooltip(cb_inf,
            "N'affiche que les fichiers suspects (--infected).\nDésactive Verbose et Afficher sains.")

        # ---- Ligne 2 : barre de progression ----
        frame_prog = ttk.LabelFrame(tab, text="Progression du scan")
        frame_prog.grid(row=2, column=0, sticky="ew", padx=10, pady=4)
        frame_prog.columnconfigure(1, weight=1)

        ttk.Label(frame_prog, text="Cible :").grid(row=0, column=0, sticky="w", padx=8, pady=2)
        self.lbl_clam_target = ttk.Label(frame_prog, text="—", foreground="#444444")
        self.lbl_clam_target.grid(row=0, column=1, sticky="w", padx=4)

        ttk.Label(frame_prog, text="Avancement :").grid(row=1, column=0, sticky="w", padx=8, pady=2)
        prog_sub = ttk.Frame(frame_prog)
        prog_sub.grid(row=1, column=1, sticky="ew", padx=4, pady=2)
        prog_sub.columnconfigure(0, weight=1)
        self.clam_progressbar = ttk.Progressbar(prog_sub, mode="determinate", maximum=100)
        self.clam_progressbar.grid(row=0, column=0, sticky="ew")
        self.lbl_clam_pct = ttk.Label(prog_sub, text="  —", width=7)
        self.lbl_clam_pct.grid(row=0, column=1, padx=(6, 0))

        ttk.Label(frame_prog, text="Détail :").grid(row=2, column=0, sticky="w", padx=8, pady=2)
        self.lbl_clam_detail = ttk.Label(frame_prog, text="—", foreground="#444444")
        self.lbl_clam_detail.grid(row=2, column=1, sticky="w", padx=4)

        ttk.Label(frame_prog, text="En cours :").grid(
            row=3, column=0, sticky="w", padx=8, pady=(2, 6))
        self.lbl_clam_current = ttk.Label(frame_prog, text="—", foreground="#666666",
                                           font=("Courier", 8))
        self.lbl_clam_current.grid(row=3, column=1, sticky="w", padx=4, pady=(2, 6))

        # ---- Ligne 3 : zone résultats ----
        frame_text = ttk.Frame(tab)
        frame_text.grid(row=3, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_clamav = scrolledtext.ScrolledText(
            frame_text, width=100, height=20, font=("Courier", 9)
        )
        self.txt_clamav.grid(row=0, column=0, sticky="nsew")

        self.clamav_controller = ClamAVController(
            on_result   =lambda txt:              self.root.after(0, self._update_clamav_output, txt),
            on_progress =lambda sc,tot,eta,spd,ln: self.root.after(0, self._update_clam_progress, sc, tot, eta, spd, ln),
            on_pre_count=lambda nf,nd:             self.root.after(0, self._update_clam_precount, nf, nd),
        )
        self._clam_total_files = 0

    # ---- Helpers ClamAV ----

    def _sync_verbose(self):
        if self.infected_only_var.get():
            self.verbose_var.set(False)
            self.show_ok_var.set(False)

    def _browse_scan_path(self):
        path = filedialog.askdirectory(
            initialdir=self.scan_path_var.get(), title="Choisir le dossier à scanner")
        if path:
            self.scan_path_var.set(path)

    def _build_scan_options(self):
        opts = []
        if self.recursive_var.get():
            opts.append("-r")
        if self.scan_mode_var.get() == "complet":
            opts += ["--max-filesize=500M", "--max-scansize=500M",
                     "--scan-archive=yes", "--scan-pdf=yes"]
        else:
            opts += ["--max-filesize=25M", "--max-scansize=25M", "--scan-archive=no"]
        if self.infected_only_var.get():
            opts.append("--infected")
        elif self.verbose_var.get():
            opts.append("--verbose")
        return opts

    def _start_clamav_scan(self):
        path = self.scan_path_var.get().strip()
        if not os.path.isdir(path):
            messagebox.showerror("Dossier invalide", f"Le dossier n'existe pas :\n{path}")
            return
        mode_label  = "complet" if self.scan_mode_var.get() == "complet" else "standard"
        recur_label = "récursif" if self.recursive_var.get() else "non récursif"
        if not messagebox.askyesno("Confirmation",
                f"Lancer un scan {mode_label} \n({recur_label}) sur :\n{path} ?"):
            return
        self.btn_clam_scan.pack_forget()
        self.btn_clam_stop.pack(side="right", padx=5)
        self._clam_total_files = 0
        self.clam_progressbar["value"] = 0
        self.lbl_clam_pct.config(text="  —")
        self.lbl_clam_target.config(text="Comptage des fichiers en cours…")
        self.lbl_clam_detail.config(text="—")
        self.lbl_clam_current.config(text="—")
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_clamav.delete(1.0, tk.END)
        self.txt_clamav.insert(
            tk.END,
            f"[{ts}] Scan ClamAV {mode_label} ({recur_label}) démarré sur : {path}\n"
            "Veuillez patienter…\n"
        )
        self.clamav_controller.scan_async(path, self._build_scan_options())

    def _stop_clamav_scan(self):
        self.clamav_controller.stop()

    def _update_clam_precount(self, nb_files, nb_dirs):
        self._clam_total_files = nb_files
        self.clam_progressbar["value"] = 0
        self.lbl_clam_target.config(
            text=(f"{nb_files:,} fichiers  ·  {nb_dirs:,} répertoires à analyser")
                  .replace(",", "\u202f")
        )
        self.lbl_clam_detail.config(text="Démarrage du scan…")

    def _update_clam_progress(self, scanned, total, eta_sec, speed, last_line):
        if total > 0:
            pct = min(100.0, scanned / total * 100)
            self.clam_progressbar["value"] = pct
            self.lbl_clam_pct.config(text=f"  {pct:5.1f}%")
        else:
            self.clam_progressbar.config(mode="indeterminate")
            self.clam_progressbar.start(20)
            self.lbl_clam_pct.config(text="  …")

        spd_txt = f"{speed:.1f} fich./s" if speed > 0 else "—"
        if eta_sec is not None and eta_sec >= 0:
            if eta_sec < 60:
                eta_txt = "moins d'1 min"
            elif eta_sec < 300:
                lo = int(eta_sec) // 60
                eta_txt = f"environ {lo}–{lo + 1} min"
            elif eta_sec < 3600:
                lo = (int(eta_sec) // 300) * 5
                eta_txt = f"environ {lo}–{lo + 5} min"
            else:
                lo_h = int(eta_sec) // 3600
                lo_m = (int(eta_sec) % 3600) // 1800 * 30
                hi_m = lo_m + 30
                eta_txt = (f"environ {lo_h}h30–{lo_h + 1}h"
                           if hi_m >= 60
                           else f"environ {lo_h}h{lo_m:02d}–{lo_h}h{hi_m:02d}")
            eta_label = f"  ·  Temps restant : {eta_txt}"
        else:
            eta_label = ""

        self.lbl_clam_detail.config(
            text=(f"{scanned:,} / {total:,} fichiers  ·  {spd_txt}{eta_label}")
                  .replace(",", "\u202f")
        )
        short = last_line if len(last_line) <= CLAM_CURRENT_MAX else "…" + last_line[-(CLAM_CURRENT_MAX - 1):]
        self.lbl_clam_current.config(text=short)

    def _update_clamav_output(self, text):
        self.clam_progressbar.stop()
        self.clam_progressbar.config(mode="determinate")
        self.clam_progressbar["value"] = 100
        self.lbl_clam_pct.config(text=" 100%")
        self.lbl_clam_current.config(text="Terminé.")
        if not self.show_ok_var.get() and not self.infected_only_var.get():
            text = "\n".join(l for l in text.splitlines() if not l.endswith(": OK"))
        self.txt_clamav.delete(1.0, tk.END)
        self.txt_clamav.insert(tk.END, text)
        self.btn_clam_stop.pack_forget()
        self.btn_clam_scan.pack(side="right", padx=5)

    def _update_clamav_db(self):
        if not messagebox.askyesno(
            "Mise à jour base virale",
            "Màj : base de données ClamAV ?\n"
            "      (Arrêt & Redémarrage :\n         clamav-freshclam)"
        ):
            return
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_clamav.delete(1.0, tk.END)
        self.txt_clamav.insert(tk.END, f"[{ts}] Mise à jour de la base virale ClamAV...\n")

        def _do_update():
            lines = []
            self._run_sudo(["systemctl", "stop", "clamav-freshclam"])
            lines.append("① Service clamav-freshclam arrêté.")
            try:
                result = subprocess.run(
                    ["sudo", "freshclam"],
                    capture_output=True, text=True
                )
                lines.append("② freshclam :\n" + (result.stdout + result.stderr).strip())
                ok = result.returncode == 0
            except Exception as e:
                lines.append(f"② Erreur freshclam : {e}")
                ok = False
            self._run_sudo(["systemctl", "start", "clamav-freshclam"])
            lines.append("③ Service clamav-freshclam redémarré.")
            self.root.after(0, self._show_clamav_db_result, "\n\n".join(lines), ok)

        threading.Thread(target=_do_update, daemon=True).start()

    def _show_clamav_db_result(self, text, ok):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if ok else "❌"
        self.txt_clamav.delete(1.0, tk.END)
        self.txt_clamav.insert(tk.END, f"[{ts}] {icon} Mise à jour base virale\n\n{text}\n")

    # =========================================================================
    #  Onglet Fail2Ban
    # =========================================================================
    def _build_tab_fail2ban(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_fail2ban = self._load_icon("fail2ban.png")
        if self.img_fail2ban:
            ttk.Label(frame_top, image=self.img_fail2ban).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="Fail2Ban – Protection SSH par bannissement d'IP",
            font=("TkDefaultFont", 12, "bold"), justify="left"
        ).pack(side="left", padx=5)

        frame_btns = ttk.LabelFrame(tab, text="Actions Fail2Ban")
        frame_btns.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        ttk.Button(frame_btns, text="🔍 Vérifier le service",
                   command=self._check_fail2ban_service, style="Info.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="▶ Démarrer Fail2Ban",
                   command=self._start_fail2ban, style="Success.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="⏹ Arrêter Fail2Ban",
                   command=self._stop_fail2ban, style="Danger.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="📋 Statut jail sshd",
                   command=self._show_fail2ban_status
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🔓 Débannir IP…",
                   command=self._unban_ip
                   ).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="🗑 Effacer",
                   command=self._clear_f2b).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Copier tout",
                   command=self._copy_f2b).pack(side="left", padx=8, pady=6)

        frame_text = ttk.Frame(tab)
        frame_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_fail2ban = scrolledtext.ScrolledText(
            frame_text, width=100, height=20, font=("Courier", 9))
        self.txt_fail2ban.grid(row=0, column=0, sticky="nsew")

    # ---- Helpers Fail2Ban ----

    def _append_f2b(self, text, success=True):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if success else "❌"
        self.txt_fail2ban.insert(tk.END, f"\n{CONSOLE_SEP}\n{icon} [{ts}]\n{text.rstrip()}\n")
        self.txt_fail2ban.see(tk.END)

    def _clear_f2b(self):
        self.txt_fail2ban.delete(1.0, tk.END)

    def _copy_f2b(self):
        self._copy_text_widget(self.txt_fail2ban)

    def _check_fail2ban_service(self):
        out, ok = self._run_sudo(["systemctl", "status", "fail2ban"])
        self._append_f2b(out, ok)

    def _ensure_jail_local(self):
        jail_local = "/etc/fail2ban/jail.local"
        _, exists  = self._run_sudo(["test", "-f", jail_local])
        if not exists:
            content = (
                "[DEFAULT]\nbantime  = 1h\nfindtime = 10m\nmaxretry = 5\nbackend  = systemd\n\n"
                "[sshd]\nenabled  = true\nport     = 22\nfilter   = sshd\nmaxretry = 4\n"
            )
            try:
                proc = subprocess.Popen(
                    ["sudo", "tee", jail_local],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True
                )
                proc.communicate(input=content)
                self._append_f2b(
                    f"{jail_local} créé automatiquement\n"
                    "(backend=systemd — nécessaire sur Raspberry Pi OS Bullseye/Bookworm).", True)
            except Exception as e:
                self._append_f2b(f"Impossible de créer {jail_local} : {e}", False)

    def _start_fail2ban(self):
        if not messagebox.askyesno("Confirmer", "Démarrer le service Fail2Ban ?"):
            return
        self._ensure_jail_local()
        out, ok = self._run_sudo(["systemctl", "start", "fail2ban"])
        if ok:
            status_out, _ = self._run_sudo(["systemctl", "status", "fail2ban"])
            self._append_f2b("Service Fail2Ban démarré.\n\n" + status_out, True)
        else:
            self._append_f2b(
                "Impossible de démarrer Fail2Ban.\n"
                "Vérifiez l'installation : sudo apt install fail2ban\n\n" + out, False)

    def _stop_fail2ban(self):
        if not messagebox.askyesno("Confirmer",
                "Arrêter le service Fail2Ban ?\nLes protections SSH seront désactivées."):
            return
        out, ok = self._run_sudo(["systemctl", "stop", "fail2ban"])
        self._append_f2b(("Service Fail2Ban arrêté.\n" if ok else "Erreur :\n") + out, ok)

    def _show_fail2ban_status(self):
        svc_out, _ = self._run_sudo(["systemctl", "is-active", "fail2ban"])
        if svc_out.strip() != "active":
            self._append_f2b(
                f"Fail2Ban n'est pas actif (état : {svc_out.strip()}).\n"
                "Utilisez '▶ Démarrer Fail2Ban' puis réessayez.", False)
            return
        out, ok = self._run_sudo(["fail2ban-client", "status", "sshd"])
        self._append_f2b(out, ok)

    def _unban_ip(self):
        banned_ips = []
        svc_out, _ = self._run_sudo(["systemctl", "is-active", "fail2ban"])
        if svc_out.strip() == "active":
            status_out, ok = self._run_sudo(["fail2ban-client", "status", "sshd"])
            if ok:
                for line in status_out.splitlines():
                    if "Banned IP list:" in line:
                        ips = line.split("Banned IP list:")[-1].strip()
                        banned_ips = [ip.strip() for ip in ips.split() if ip.strip()]

        dialog = tk.Toplevel(self.root)
        dialog.title("Débannir IP")
        dialog.resizable(False, False)
        ttk.Label(dialog, text="Adresse IP à débannir :").pack(padx=16, pady=(12, 4))
        ip_var = tk.StringVar()
        if banned_ips:
            ttk.Label(dialog,
                text=f"{len(banned_ips)} IP bannies — sélectionnez ou saisissez :",
                foreground="gray").pack(padx=16, anchor="w")
            combo = ttk.Combobox(dialog, textvariable=ip_var, values=banned_ips, width=26)
            combo.pack(padx=16, pady=4)
            combo.focus()
        else:
            entry = ttk.Entry(dialog, textvariable=ip_var, width=26)
            entry.pack(padx=16, pady=4)
            entry.focus()
            if svc_out.strip() == "active":
                ttk.Label(dialog, text="(aucune IP bannie actuellement)",
                          foreground="gray").pack(padx=16)

        def do_unban():
            ip = ip_var.get().strip()
            if not ip:
                return
            dialog.destroy()
            out, ok = self._run_sudo(["fail2ban-client", "set", "sshd", "unbanip", ip])
            self._append_f2b(
                (f"IP {ip} débannie avec succès.\n" if ok
                 else f"Impossible de débannir {ip} :\n") + out, ok)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Débannir", command=do_unban,
                   style="Danger.TButton").pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Annuler",
                   command=dialog.destroy).pack(side="left", padx=8)
        dialog.bind("<Return>", lambda e: do_unban())

    # =========================================================================
    #  Onglet UFW
    # =========================================================================
    def _build_tab_ufw(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_ufw = self._load_icon("ufw.png", (200, 200))
        if self.img_ufw:
            ttk.Label(frame_top, image=self.img_ufw).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="UFW (Uncomplicated Firewall) – Pare-feu",
            font=("TkDefaultFont", 12, "bold")
        ).pack(side="left", padx=5)

        frame_btns = ttk.LabelFrame(tab, text="Actions UFW")
        frame_btns.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        ttk.Button(frame_btns, text="🔍 Statut UFW",
                   command=self._ufw_status, style="Info.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="▶ Activer UFW",
                   command=self._ufw_enable, style="Success.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="⏹ Désactiver UFW",
                   command=self._ufw_disable, style="Danger.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="📋 Voir les règles",
                   command=self._ufw_list_rules).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🗑 Effacer",
                   command=lambda: self.txt_ufw.delete(1.0, tk.END)
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Copier tout",
                   command=lambda: self._copy_text_widget(self.txt_ufw)
                   ).pack(side="left", padx=8, pady=6)

        frame_text = ttk.Frame(tab)
        frame_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_ufw = scrolledtext.ScrolledText(frame_text, width=100, height=20,
                                                  font=("Courier", 9))
        self.txt_ufw.grid(row=0, column=0, sticky="nsew")

    # ---- Helpers UFW ----

    def _append_ufw(self, text, success=True):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if success else "❌"
        self.txt_ufw.insert(tk.END, f"\n{CONSOLE_SEP}\n{icon} [{ts}]\n{text.rstrip()}\n")
        self.txt_ufw.see(tk.END)

    def _ufw_status(self):
        out, ok = self._run_sudo(["ufw", "status", "verbose"])
        if not ok and "not found" in out.lower():
            self._append_ufw("UFW n'est pas installé.\nInstallez-le : sudo apt install ufw", False)
        else:
            self._append_ufw(out, ok)

    def _ufw_enable(self):
        if not messagebox.askyesno("Activer UFW", "Activer le pare-feu UFW ?"):
            return
        out, ok   = self._run_sudo(["ufw", "--force", "enable"])
        status, _ = self._run_sudo(["ufw", "status", "verbose"])
        self._append_ufw(out.strip() + "\n" + status.strip(), ok)

    def _ufw_disable(self):
        if not messagebox.askyesno("Désactiver... ",
                                    "Désactiver le pare-feu ?\n(Pi5 moins bien protégé)"):
            return
        out, ok = self._run_sudo(["ufw", "disable"])
        self._append_ufw(out, ok)

    def _ufw_list_rules(self):
        lines = []
        out, ok = self._run_sudo(["ufw", "status", "numbered"])
        lines.append("=== Règles actives ===\n" + out.strip())
        for rules_file in ["/etc/ufw/user.rules", "/etc/ufw/user6.rules"]:
            out, _ = self._run_sudo(["cat", rules_file])
            lines.append(f"=== {rules_file} ===\n" + out.strip())
        self._append_ufw("\n\n".join(lines), ok)

    # =========================================================================
    #  Onglet Wireshark
    # =========================================================================
    def _build_tab_wireshark(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_wireshark = self._load_icon("wireshark.png", (150, 150))
        if self.img_wireshark:
            ttk.Label(frame_top, image=self.img_wireshark).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="Wireshark – Surveillance du trafic réseau",
            font=("TkDefaultFont", 12, "bold")
        ).pack(side="left", padx=5)

        frame_btns = ttk.LabelFrame(tab, text="Analyse réseau")
        frame_btns.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        ttk.Button(frame_btns, text="⚙️ Analyser le réseau (10 sec.)",
                   command=self._ws_capture, style="Info.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🖥 Appareils connectés",
                   command=self._ws_devices).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🔍 Voir les intrusions réseau",
                   command=self._ws_intrusions, style="Danger.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="🖱 Lancer Wireshark (GUI)",
                   command=self._ws_launch_gui).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🗑 Effacer",
                   command=lambda: self.txt_ws.delete(1.0, tk.END)
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Copier tout",
                   command=lambda: self._copy_text_widget(self.txt_ws)
                   ).pack(side="left", padx=8, pady=6)

        frame_text = ttk.Frame(tab)
        frame_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_ws = scrolledtext.ScrolledText(frame_text, width=100, height=20,
                                                 font=("Courier", 9))
        self.txt_ws.grid(row=0, column=0, sticky="nsew")

    # ---- Helpers Wireshark ----

    def _append_ws(self, text, success=True):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if success else "❌"
        self.txt_ws.insert(tk.END, f"\n{CONSOLE_SEP}\n{icon} [{ts}]\n{text.rstrip()}\n")
        self.txt_ws.see(tk.END)

    def _ws_check_tshark(self):
        try:
            subprocess.run(["which", "tshark"], capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            self._append_ws(
                "tshark n'est pas installé.\n"
                "Installez Wireshark/tshark :\n"
                "  sudo apt install wireshark tshark -y\n"
                "  sudo usermod -aG wireshark $USER", False)
            return False

    def _ws_get_iface(self):
        try:
            out = subprocess.run(
                ["ip", "route", "get", "1.1.1.1"],
                capture_output=True, text=True
            ).stdout
            for part in out.split():
                if part not in ("via", "dev", "src", "uid") and "." not in part and part.isidentifier():
                    return part
        except Exception:
            pass
        return "eth0"

    def _ws_capture(self):
        if not self._ws_check_tshark():
            return
        iface = self._ws_get_iface()
        self._append_ws(f"Capture réseau 10 secondes sur {iface}...", True)

        def _capture():
            result = subprocess.run(
                ["sudo", "tshark", "-i", iface, "-a", "duration:10", "-q", "-z", "conv,ip"],
                capture_output=True, text=True
            )
            out = (result.stdout + result.stderr).strip() or "Aucun résultat."
            self.root.after(0, self._append_ws, out, True)

        threading.Thread(target=_capture, daemon=True).start()

    def _ws_devices(self):
        self._append_ws("Recherche des appareils connectés...", True)

        def _scan():
            try:
                iface  = self._ws_get_iface()
                result = subprocess.run(
                    ["sudo", "arp-scan", "--interface=" + iface, "--localnet"],
                    capture_output=True, text=True
                )
                out = result.stdout or result.stderr
            except FileNotFoundError:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
                out = ("arp-scan non installé — résultats via arp -a :\n"
                       "(Pour plus de détails : sudo apt install arp-scan)\n\n"
                       + result.stdout)
            self.root.after(0, self._append_ws, out.strip(), True)

        threading.Thread(target=_scan, daemon=True).start()

    def _ws_intrusions(self):
        self._append_ws("Analyse des connexions actives suspectes...", True)

        def _check():
            lines = []
            for cmd, label in [
                (["ss", "-tnp", "state", "established"], "── Connexions établies ──"),
                (["ss", "-tlnp"],                        "\n── Ports en écoute ──"),
            ]:
                result = subprocess.run(cmd, capture_output=True, text=True)
                lines.append(f"{label}\n{result.stdout.strip()}")
            result = subprocess.run(
                ["sudo", "journalctl", "-u", "ssh", "-n", "20", "--no-pager"],
                capture_output=True, text=True
            )
            lines.append("\n── 20 derniers événements SSH ──\n" + result.stdout.strip())
            self.root.after(0, self._append_ws, "\n".join(lines), True)

        threading.Thread(target=_check, daemon=True).start()

    def _ws_launch_gui(self):
        try:
            subprocess.Popen(["wireshark"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._append_ws(
                "Wireshark lancé en arrière-plan.\n"
                "⚠️  Ne pas lancer en root — utilisez votre compte utilisateur.", True)
        except FileNotFoundError:
            self._append_ws(
                "Wireshark n'est pas installé.\n"
                "Installez-le : sudo apt install wireshark -y\n"
                "Puis ajoutez votre user au groupe : sudo usermod -aG wireshark $USER", False)

    # =========================================================================
    #  Onglet WireGuard VPN
    # =========================================================================
    def _build_tab_wireguard(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_wireguard = self._load_icon("wireguard.png", (80, 80))
        if self.img_wireguard:
            ttk.Label(frame_top, image=self.img_wireguard).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="WireGuard – VPN sécurisé",
            font=("TkDefaultFont", 12, "bold")
        ).pack(side="left", padx=5)

        frame_btns = ttk.LabelFrame(tab, text="Actions WireGuard")
        frame_btns.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        ttk.Button(frame_btns, text="📋 Générer les clés",
                   command=self._wg_genkeys).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="⚙️ Créer wg0.conf",
                   command=self._wg_create_conf).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="▶ Démarrer wg0",
                   command=self._wg_start, style="Success.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="⏹ Arrêter wg0",
                   command=self._wg_stop, style="Danger.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🔍 Statut",
                   command=self._wg_status).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="🗑 Effacer",
                   command=lambda: self.txt_wg.delete(1.0, tk.END)
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Copier tout",
                   command=lambda: self._copy_text_widget(self.txt_wg)
                   ).pack(side="left", padx=8, pady=6)

        frame_info = ttk.LabelFrame(tab, text="ℹ️  Rappel configuration")
        frame_info.grid(row=2, column=0, sticky="ew", padx=10, pady=4)
        ttk.Label(
            frame_info,
            text="Prérequis : réserver une IP fixe dans la Livebox pour chaque appareil client",
            foreground="gray", justify="left", font=("TkDefaultFont", 8)
        ).pack(padx=8, pady=4, anchor="w")

        frame_auto = ttk.LabelFrame(tab, text="Démarrage automatique au reboot")
        frame_auto.grid(row=3, column=0, sticky="ew", padx=10, pady=4)
        ttk.Label(frame_auto,
                  text="Active ou désactive wg0 au démarrage du Pi :",
                  foreground="gray", font=("TkDefaultFont", 8)
                  ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_auto, text="✅ Activer au démarrage",
                   command=self._wg_enable_autostart, style="Success.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_auto, text="❌ Désactiver au démarrage",
                   command=self._wg_disable_autostart, style="Danger.TButton"
                   ).pack(side="left", padx=8, pady=6)

        frame_text = ttk.Frame(tab)
        frame_text.grid(row=4, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_wg = scrolledtext.ScrolledText(frame_text, width=100, height=16,
                                                 font=("Courier", 9))
        self.txt_wg.grid(row=0, column=0, sticky="nsew")

    # ---- Helpers WireGuard ----

    def _append_wg(self, text, success=True):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if success else "❌"
        self.txt_wg.insert(tk.END, f"\n{CONSOLE_SEP}\n{icon} [{ts}]\n{text.rstrip()}\n")
        self.txt_wg.see(tk.END)

    def _wg_genkeys(self):
        if not messagebox.askyesno(
            "Générer les clés WireGuard",
            "Générer une nouvelle paire de clés serveur ?\n"
            "Les clés seront sauvegardées dans /etc/wireguard/"
        ):
            return
        try:
            privkey = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True, check=True
            ).stdout.strip()
            pubkey  = subprocess.run(
                ["wg", "pubkey"], input=privkey, capture_output=True, text=True, check=True
            ).stdout.strip()
            for fname, content in [("server_private.key", privkey),
                                    ("server_public.key",  pubkey)]:
                proc = subprocess.Popen(
                    ["sudo", "tee", f"/etc/wireguard/{fname}"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True
                )
                proc.communicate(input=content)
            subprocess.run(["sudo", "chmod", "600", "/etc/wireguard/server_private.key"])
            self._append_wg(
                f"Clés générées et sauvegardées dans /etc/wireguard/\n\n"
                f"Clé publique serveur :\n{pubkey}\n\n"
                f"⚠️  Gardez la clé privée secrète — ne la partagez jamais.", True)
        except FileNotFoundError:
            self._append_wg("WireGuard n'est pas installé.\n"
                            "Installez-le : sudo apt install wireguard -y", False)
        except Exception as e:
            self._append_wg(f"Erreur génération clés : {e}", False)

    def _wg_create_conf(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Créer /etc/wireguard/wg0.conf")
        dialog.resizable(False, False)
        fields = [
            ("IP du Pi sur le VPN (ex: 10.221.90.1/24)", WG_DEFAULT_VPN_IP),
            ("Port d'écoute WireGuard",                   WG_DEFAULT_PORT),
            ("Interface réseau du Pi (wifi - wlan0)",      self._ws_get_iface()),
        ]
        vars_ = []
        for i, (label, default) in enumerate(fields):
            ttk.Label(dialog, text=label).grid(row=i, column=0, padx=12, pady=4, sticky="w")
            v = tk.StringVar(value=default)
            ttk.Entry(dialog, textvariable=v, width=28).grid(row=i, column=1, padx=8, pady=4)
            vars_.append(v)
        ttk.Label(dialog,
                  text="La clé privée sera lue depuis /etc/wireguard/server_private.key",
                  foreground="gray", font=("TkDefaultFont", 8)
                  ).grid(row=len(fields), column=0, columnspan=2, padx=12, pady=4)

        def create():
            vpn_ip, port, iface = [v.get().strip() for v in vars_]
            try:
                privkey_out = subprocess.run(
                    ["sudo", "cat", "/etc/wireguard/server_private.key"],
                    capture_output=True, text=True
                ).stdout.strip()
            except Exception:
                privkey_out = "VOTRE_CLE_PRIVEE_ICI"
            conf = (
                f"[Interface]\nAddress    = {vpn_ip}\nListenPort = {port}\n"
                f"PrivateKey = {privkey_out}\n\n"
                f"# Activer le routage\n"
                f"PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; "
                f"iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE\n"
                f"PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; "
                f"iptables -t nat -D POSTROUTING -o {iface} -j MASQUERADE\n\n"
                f"# ── Ajoutez ici un bloc [Peer] par appareil client ──\n"
                f"# [Peer]\n# PublicKey  = CLE_PUBLIQUE_CLIENT\n# AllowedIPs = 10.0.0.2/32\n"
            )
            proc = subprocess.Popen(
                ["sudo", "tee", "/etc/wireguard/wg0.conf"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True
            )
            proc.communicate(input=conf)
            subprocess.run(["sudo", "chmod", "600", "/etc/wireguard/wg0.conf"])
            dialog.destroy()
            self._append_wg("Fichier /etc/wireguard/wg0.conf créé :\n\n" + conf, True)

        btn_f = ttk.Frame(dialog)
        btn_f.grid(row=len(fields) + 1, column=0, columnspan=2, pady=10)
        ttk.Button(btn_f, text="✅ Créer le fichier", command=create,
                   style="Success.TButton").pack(side="left", padx=8)
        ttk.Button(btn_f, text="Annuler", command=dialog.destroy).pack(side="left", padx=8)

    def _wg_start(self):
        out, ok = self._run_sudo(["wg-quick", "up", "wg0"])
        self._append_wg(out if out.strip() else "Interface wg0 démarrée.", ok)
        if ok:
            self._wg_status()

    def _wg_stop(self):
        if not messagebox.askyesno("Arrêter WireGuard", "Arrêter l'interface wg0 ?"):
            return
        out, ok = self._run_sudo(["wg-quick", "down", "wg0"])
        self._append_wg(out if out.strip() else "Interface wg0 arrêtée.", ok)

    def _wg_status(self):
        out, ok = self._run_sudo(["wg", "show"])
        if not out.strip():
            out = "WireGuard n'est pas actif (aucune interface wg0 en cours)."
            ok  = False
        self._append_wg(out, ok)

    def _wg_enable_autostart(self):
        if not messagebox.askyesno("Activer au démarrage",
                "WireGuard (wg0) démarrera automatiquement à chaque reboot.\nConfirmer ?"):
            return
        out, ok   = self._run_sudo(["systemctl", "enable", "wg-quick@wg0"])
        state, _  = self._run_sudo(["systemctl", "is-enabled", "wg-quick@wg0"])
        self._append_wg(
            f"Démarrage automatique activé.\nÉtat : {state.strip()}\n\n{out.strip()}" if ok
            else f"Erreur lors de l'activation :\n{out}", ok)

    def _wg_disable_autostart(self):
        if not messagebox.askyesno("Désactiver au démarrage",
                "WireGuard (wg0) ne démarrera plus automatiquement au reboot.\nConfirmer ?"):
            return
        out, ok  = self._run_sudo(["systemctl", "disable", "wg-quick@wg0"])
        state, _ = self._run_sudo(["systemctl", "is-enabled", "wg-quick@wg0"])
        self._append_wg(
            f"Démarrage automatique désactivé.\nÉtat : {state.strip()}\n\n{out.strip()}" if ok
            else f"Erreur lors de la désactivation :\n{out}", ok)

    # =========================================================================
    #  Onglet Audit Sécurité — Hydra & Nmap
    # =========================================================================
    def _build_tab_audit(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_hydra = self._load_icon("hydra.png", (200, 200))
        if self.img_hydra:
            ttk.Label(frame_top, image=self.img_hydra).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="Audit Sécurité – Hydra & Nmap",
            font=("TkDefaultFont", 12, "bold")
        ).pack(side="left", padx=5)

        frame_warn = ttk.Frame(tab)
        frame_warn.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 2))
        ttk.Label(
            frame_warn,
            text="⚠️  Usage légal uniquement sur systèmes personnels. "
                 "Hydra est un outil d'attaque par force brute — "
                 "son utilisation sur des systèmes tiers est illégale.",
            foreground="#cc6600", font=("TkDefaultFont", 8, "italic"), wraplength=900
        ).pack(anchor="w", padx=8, pady=2)

        # ---- Hydra ----
        frame_hydra = ttk.LabelFrame(tab, text="Hydra – Test de robustesse SSH")
        frame_hydra.grid(row=2, column=0, sticky="ew", padx=10, pady=4)
        frame_hydra.columnconfigure(1, weight=1)

        ttk.Label(frame_hydra, text="Cible (IP du Pi) :").grid(
            row=0, column=0, sticky="w", padx=8, pady=4)
        self.hydra_target_var = tk.StringVar(value=HYDRA_DEFAULT_TARGET)
        ttk.Entry(frame_hydra, textvariable=self.hydra_target_var, width=18).grid(
            row=0, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame_hydra, text="Utilisateur SSH :").grid(
            row=0, column=2, sticky="w", padx=8, pady=4)
        self.hydra_user_var = tk.StringVar(value=HYDRA_DEFAULT_USER)
        ttk.Entry(frame_hydra, textvariable=self.hydra_user_var, width=14).grid(
            row=0, column=3, sticky="w", padx=4, pady=4)

        ttk.Label(frame_hydra, text="Liste de mots de passe :").grid(
            row=1, column=0, sticky="w", padx=8, pady=4)
        self.hydra_wordlist_var = tk.StringVar(value=HYDRA_DEFAULT_WORDLIST)
        ttk.Entry(frame_hydra, textvariable=self.hydra_wordlist_var, width=40).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=4, pady=4)
        ttk.Button(frame_hydra, text="▶ Parcourir",
                   command=self._audit_browse_wordlist).grid(row=1, column=3, padx=4, pady=4)

        ttk.Label(frame_hydra, text="Nb tâches parallèles :").grid(
            row=2, column=0, sticky="w", padx=8, pady=4)
        self.hydra_tasks_var = tk.StringVar(value=HYDRA_DEFAULT_TASKS)
        ttk.Entry(frame_hydra, textvariable=self.hydra_tasks_var, width=6).grid(
            row=2, column=1, sticky="w", padx=4, pady=4)
        self._add_tooltip(
            ttk.Label(frame_hydra, text="(conseil : 4 pour SSH sur Pi)"),
            "Trop de tâches parallèles peut faire planter SSH.\n4 est une valeur sûre.")

        btn_hydra_frame = ttk.Frame(frame_hydra)
        btn_hydra_frame.grid(row=3, column=0, columnspan=4, pady=6)
        self.btn_hydra_run = ttk.Button(btn_hydra_frame, text="▶ Lancer Test Hydra",
                                         command=self._audit_run_hydra, style="Success.TButton")
        self.btn_hydra_run.pack(side="left", padx=8)
        self.btn_hydra_stop = ttk.Button(btn_hydra_frame, text="⏹ Arrêter",
                                          command=self._audit_stop_hydra, style="Danger.TButton")

        # ---- Nmap ----
        frame_nmap = ttk.LabelFrame(tab, text="Nmap – Scanner les ports ouverts")
        frame_nmap.grid(row=3, column=0, sticky="ew", padx=10, pady=4)
        ttk.Label(frame_nmap, text="Cible (IP ou nom) :").grid(
            row=0, column=0, sticky="w", padx=8, pady=4)
        self.nmap_target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(frame_nmap, textvariable=self.nmap_target_var, width=20).grid(
            row=0, column=1, sticky="w", padx=4, pady=4)

        self.nmap_mode_var = tk.StringVar(value="rapide")
        modes_nmap = [
            ("Rapide (-F)",         "rapide",   "Scan des 100 ports les plus courants"),
            ("Complet (-p 1-65535)","complet",  "Scan de tous les ports — lent"),
            ("Détection services",  "services", "Identifie les services et versions (-sV)"),
        ]
        nmap_mode_frame = ttk.Frame(frame_nmap)
        nmap_mode_frame.grid(row=0, column=2, columnspan=3, sticky="w", padx=8)
        for label, val, tip in modes_nmap:
            rb = ttk.Radiobutton(nmap_mode_frame, text=label, value=val,
                                  variable=self.nmap_mode_var)
            rb.pack(side="left", padx=8)
            self._add_tooltip(rb, tip)

        btn_nmap_frame = ttk.Frame(frame_nmap)
        btn_nmap_frame.grid(row=1, column=0, columnspan=5, pady=6)
        ttk.Button(btn_nmap_frame, text="▶ Lancer Scan Nmap",
                   command=self._audit_run_nmap, style="Success.TButton"
                   ).pack(side="left", padx=8)

        # ---- Console ----
        frame_text = ttk.Frame(tab)
        frame_text.grid(row=4, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_audit = scrolledtext.ScrolledText(frame_text, width=100, height=12,
                                                    font=("Courier", 9))
        self.txt_audit.grid(row=0, column=0, sticky="nsew")

        frame_audit_btns = ttk.Frame(tab)
        frame_audit_btns.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 6))
        ttk.Button(frame_audit_btns, text="🗑 Effacer",
                   command=lambda: self.txt_audit.delete(1.0, tk.END)
                   ).pack(side="left", padx=8)
        ttk.Button(frame_audit_btns, text="📋 Copier tout",
                   command=lambda: self._copy_text_widget(self.txt_audit)
                   ).pack(side="left", padx=8)
        self._hydra_process = None

    # ---- Helpers Audit ----

    def _append_audit(self, text, success=True):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if success else "❌"
        self.txt_audit.insert(tk.END, f"\n{CONSOLE_SEP}\n{icon} [{ts}]\n{text.rstrip()}\n")
        self.txt_audit.see(tk.END)

    def _audit_browse_wordlist(self):
        path = filedialog.askopenfilename(
            title="Choisir une liste de mots de passe",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous", "*")])
        if path:
            self.hydra_wordlist_var.set(path)

    def _audit_run_hydra(self):
        target = self.hydra_target_var.get().strip()
        user   = self.hydra_user_var.get().strip()
        wlist  = self.hydra_wordlist_var.get().strip()
        tasks  = self.hydra_tasks_var.get().strip()
        if not target or not user or not wlist:
            messagebox.showerror("Paramètres manquants",
                                  "Renseignez la cible, l'utilisateur et la liste.")
            return
        if not os.path.isfile(wlist):
            messagebox.showerror("Fichier introuvable",
                                  f"Liste de mots de passe introuvable :\n{wlist}")
            return
        if not messagebox.askyesno(
            "Lancer Hydra",
            f"Tester la robustesse SSH de {target} avec l'utilisateur '{user}' ?\n"
            "⚠️  Uniquement sur vos propres systèmes."
        ):
            return
        self.btn_hydra_run.pack_forget()
        self.btn_hydra_stop.pack(side="left", padx=8)
        self._append_audit(f"Hydra démarré sur {target} / user:{user}...", True)

        def _run():
            cmd = ["hydra", "-l", user, "-P", wlist, "-t", tasks,
                   "-V", "-o", "/tmp/hydra_result.txt", f"ssh://{target}"]
            try:
                self._hydra_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                out, _ = self._hydra_process.communicate()
                ok     = self._hydra_process.returncode in (0, 1)
            except Exception as e:
                out, ok = f"Erreur : {e}", False
            finally:
                self._hydra_process = None
            self.root.after(0, self._audit_hydra_done, out, ok)

        threading.Thread(target=_run, daemon=True).start()

    def _audit_stop_hydra(self):
        if self._hydra_process and self._hydra_process.poll() is None:
            self._hydra_process.terminate()

    def _audit_hydra_done(self, text, ok):
        self._append_audit(text, ok)
        self.btn_hydra_stop.pack_forget()
        self.btn_hydra_run.pack(side="left", padx=8)
        found_pwd = None
        for line in text.splitlines():
            if "[ssh]" in line and "password:" in line:
                parts = line.split("password:")
                if len(parts) > 1:
                    found_pwd = parts[1].strip().split()[0]
                    break
        if found_pwd:
            def _cracklib_check():
                try:
                    result  = subprocess.run(
                        ["cracklib-check"],
                        input=found_pwd + "\n", capture_output=True, text=True
                    )
                    output  = result.stdout.strip()
                    verdict = output.split(":", 1)[-1].strip() if ":" in output else output
                    self.root.after(0, self._audit_cracklib_result, found_pwd, verdict)
                except FileNotFoundError:
                    self.root.after(0, self._audit_cracklib_result, found_pwd,
                                    "cracklib-check introuvable (sudo apt install libcrack2)")
                except Exception as e:
                    self.root.after(0, self._audit_cracklib_result, found_pwd, f"Erreur : {e}")
            threading.Thread(target=_cracklib_check, daemon=True).start()

    def _audit_cracklib_result(self, password, verdict):
        verdict_lc = verdict.lower()
        if verdict_lc == "ok":
            quality = "✅ Qualité : Acceptable  (mais déjà dans une wordlist !)"
            tag     = "audit_ok"
        elif any(k in verdict_lc for k in ("too short", "trop court")):
            quality = f"🔴 Qualité : Très Faible  ({verdict})"
            tag     = "audit_bad"
        elif any(k in verdict_lc for k in ("dictionary", "dictionn")):
            quality = f"🔴 Qualité : Mot du Dictionnaire  ({verdict})"
            tag     = "audit_bad"
        elif any(k in verdict_lc for k in ("simple", "trivial", "weak")):
            quality = f"🟠 Qualité : Faible  ({verdict})"
            tag     = "audit_warn"
        else:
            quality = f"🟠 Qualité : Médiocre  ({verdict})"
            tag     = "audit_warn"

        ts  = datetime.now().strftime("%H:%M:%S")
        msg = (
            f"\n{CONSOLE_SEP}\n"
            f"🔑 [{ts}] Évaluation cracklib du mot de passe trouvé par Hydra\n"
            f"   Mot de passe : {'*' * len(password)}  ({len(password)} caractères)\n"
            f"   {quality}\n"
            f"   ⚠️  Ce mot de passe figure dans une wordlist — A Changer Immédiatement.\n"
        )
        self.txt_audit.insert(tk.END, msg)
        self.txt_audit.tag_configure("audit_bad",  foreground="#cc0000",
                                      font=("Courier", 9, "bold"))
        self.txt_audit.tag_configure("audit_warn", foreground="#cc6600",
                                      font=("Courier", 9, "bold"))
        self.txt_audit.tag_configure("audit_ok",   foreground="#007700",
                                      font=("Courier", 9, "bold"))
        lines = self.txt_audit.get(1.0, tk.END).splitlines()
        for i, ln in enumerate(lines):
            if (quality.split("(")[0].strip() in ln
                    or ln.strip().startswith(("🔴", "🟠", "✅"))):
                self.txt_audit.tag_add(tag, f"{i + 1}.0", f"{i + 1}.end")
        self.txt_audit.see(tk.END)

    def _audit_run_nmap(self):
        target = self.nmap_target_var.get().strip()
        if not target:
            messagebox.showerror("Cible manquante", "Entrez une IP ou un nom d'hôte.")
            return
        mode = self.nmap_mode_var.get()
        if mode == "rapide":
            flags, label = ["-F"],             "rapide (-F)"
        elif mode == "complet":
            flags, label = ["-p", "1-65535"],  "complet (tous ports)"
        else:
            flags, label = ["-sV"],            "détection services (-sV)"
        self._append_audit(f"Nmap {label} sur {target}...", True)

        def _run():
            result = subprocess.run(
                ["nmap"] + flags + [target],
                capture_output=True, text=True
            )
            if result.returncode not in (0, 1) and not result.stdout:
                out = result.stderr or "Nmap n'est pas installé.\nInstallez-le : sudo apt install nmap -y"
                ok  = False
            else:
                out = result.stdout or result.stderr
                ok  = True
            self.root.after(0, self._append_audit, out, ok)

        threading.Thread(target=_run, daemon=True).start()

    # =========================================================================
    #  Onglet Audit Mot de Passe — Cracklib-check
    # =========================================================================
    def _build_tab_passwd(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_passwd = self._load_icon("Logo_Check2.png")
        if self.img_passwd:
            ttk.Label(frame_top, image=self.img_passwd).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="🔑  Audit Mot de Passe – Cracklib-check",
            font=("TkDefaultFont", 12, "bold"),
        ).pack(side="left", padx=5)

        ttk.Label(
            tab,
            text="Évalue la solidité d'un mot de passe ou de toute une liste (wordlist).\n"
                 "Les mots de passe saisis ne sont jamais stockés ni transmis.",
            foreground="#444444", font=("TkDefaultFont", 8, "italic"), wraplength=900,
        ).grid(row=1, column=0, sticky="w", padx=18, pady=(0, 4))

        # ---- Section saisie manuelle ----
        frame_manual = ttk.LabelFrame(tab, text="① Analyse d'un mot de passe")
        frame_manual.grid(row=2, column=0, sticky="ew", padx=10, pady=4)
        frame_manual.columnconfigure(1, weight=1)

        ttk.Label(frame_manual, text="Mot de passe :").grid(
            row=0, column=0, sticky="w", padx=8, pady=6)
        self._pwd_show_var  = tk.BooleanVar(value=False)
        self._pwd_entry_var = tk.StringVar()
        self._pwd_entry = ttk.Entry(
            frame_manual, textvariable=self._pwd_entry_var, width=36, show="●")
        self._pwd_entry.grid(row=0, column=1, sticky="w", padx=4, pady=6)
        self._pwd_entry.bind("<Return>", lambda e: self._passwd_analyze_single())
        ttk.Checkbutton(
            frame_manual, text="Afficher",
            variable=self._pwd_show_var, command=self._passwd_toggle_show
        ).grid(row=0, column=2, padx=6)

        frame_strength = ttk.Frame(frame_manual)
        frame_strength.grid(row=1, column=0, columnspan=3, sticky="ew", padx=4, pady=(2, 4))
        ttk.Label(frame_strength, text="Force :").pack(side="left", padx=(4, 6))
        self._pwd_strength_canvas = tk.Canvas(
            frame_strength, height=18, width=220, bg="#e0e0e0",
            highlightthickness=1, highlightbackground="#aaaaaa"
        )
        self._pwd_strength_canvas.pack(side="left")
        self._pwd_strength_label = ttk.Label(frame_strength, text="—")
        self._pwd_strength_label.pack(side="left", padx=10)
        self._pwd_entry_var.trace_add("write", self._passwd_live_strength)

        btn_row = ttk.Frame(frame_manual)
        btn_row.grid(row=2, column=0, columnspan=3, pady=6)
        self.btn_pwd_analyze = ttk.Button(
            btn_row, text="🔍 Analyser avec cracklib",
            command=self._passwd_analyze_single, style="Info.TButton")
        self.btn_pwd_analyze.pack(side="left", padx=8)
        ttk.Button(
            btn_row, text="🗑 Effacer champ",
            command=lambda: self._pwd_entry_var.set("")
        ).pack(side="left", padx=8)

        # ---- Section wordlist ----
        frame_wl = ttk.LabelFrame(tab, text="② Analyse d'une liste (wordlist)")
        frame_wl.grid(row=3, column=0, sticky="ew", padx=10, pady=4)
        frame_wl.columnconfigure(1, weight=1)

        ttk.Label(frame_wl, text="Fichier .txt :").grid(
            row=0, column=0, sticky="w", padx=8, pady=6)
        self._wl_path_var = tk.StringVar(value=PASSWD_DEFAULT_WORDLIST)
        ttk.Entry(frame_wl, textvariable=self._wl_path_var, width=50).grid(
            row=0, column=1, sticky="ew", padx=4, pady=6)
        ttk.Button(frame_wl, text="▶ Parcourir",
                   command=self._passwd_browse_wordlist).grid(row=0, column=2, padx=4, pady=6)

        ttk.Label(frame_wl, text="Nb de lignes à analyser :").grid(
            row=1, column=0, sticky="w", padx=8, pady=4)
        frame_limit = ttk.Frame(frame_wl)
        frame_limit.grid(row=1, column=1, sticky="w", padx=4, pady=4)
        self._wl_limit_var = tk.StringVar(value=PASSWD_DEFAULT_LIMIT)
        ttk.Entry(frame_limit, textvariable=self._wl_limit_var, width=8).pack(side="left")
        ttk.Label(frame_limit, text="  (max conseillé : 500)",
                  foreground="#888888", font=("TkDefaultFont", 8)).pack(side="left")

        btn_row2 = ttk.Frame(frame_wl)
        btn_row2.grid(row=2, column=0, columnspan=3, pady=6)
        self.btn_wl_run = ttk.Button(
            btn_row2, text="▶ Analyser la liste",
            command=self._passwd_analyze_wordlist, style="Success.TButton")
        self.btn_wl_run.pack(side="left", padx=8)
        self.btn_wl_stop = ttk.Button(
            btn_row2, text="⏹ Arrêter",
            command=self._passwd_stop_wordlist, style="Danger.TButton")
        self._wl_running = False

        self._wl_progress = ttk.Progressbar(frame_wl, length=400, maximum=100)
        self._wl_progress.grid(row=3, column=0, columnspan=3, sticky="ew", padx=8, pady=(0, 6))
        self._wl_progress_lbl = ttk.Label(frame_wl, text="", foreground="#444444")
        self._wl_progress_lbl.grid(row=4, column=0, columnspan=3, sticky="w", padx=8, pady=(0, 4))

        # ---- Console résultats ----
        frame_text = ttk.Frame(tab)
        frame_text.grid(row=4, column=0, sticky="nsew", padx=10, pady=(4, 4))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_passwd = scrolledtext.ScrolledText(
            frame_text, width=100, height=14, font=("Courier", 9))
        self.txt_passwd.grid(row=0, column=0, sticky="nsew")
        self.txt_passwd.tag_configure("good",   foreground="#007700", font=("Courier", 9, "bold"))
        self.txt_passwd.tag_configure("warn",   foreground="#cc6600", font=("Courier", 9, "bold"))
        self.txt_passwd.tag_configure("bad",    foreground="#cc0000", font=("Courier", 9, "bold"))
        self.txt_passwd.tag_configure("header", foreground="#0055aa", font=("Courier", 9, "bold"))

        frame_btns_pw = ttk.Frame(tab)
        frame_btns_pw.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 6))
        ttk.Button(frame_btns_pw, text="🗑 Effacer",
                   command=lambda: self.txt_passwd.delete(1.0, tk.END)
                   ).pack(side="left", padx=8)
        ttk.Button(frame_btns_pw, text="📋 Copier tout",
                   command=lambda: self._copy_text_widget(self.txt_passwd)
                   ).pack(side="left", padx=8)
        self._wl_thread = None

    # ---- Helpers Audit Mot de Passe ----

    def _passwd_toggle_show(self):
        self._pwd_entry.config(show="" if self._pwd_show_var.get() else "●")

    def _passwd_live_strength(self, *_):
        pwd        = self._pwd_entry_var.get()
        score, details = self._compute_strength(pwd)
        total_width = 260
        bar_w = int(total_width * score / 100)
        color = "#cc0000" if score < 35 else ("#cc6600" if score < 65 else "#007700")
        self._pwd_strength_canvas.delete("all")
        if bar_w > 0:
            self._pwd_strength_canvas.create_rectangle(0, 0, bar_w, 18, fill=color, outline="")
        label = ("Très faible" if score < 20 else
                 "Faible"      if score < 40 else
                 "Moyen"       if score < 60 else
                 "Bon"         if score < 80 else "Excellent")
        self._pwd_strength_label.config(
            text=f"{label}  ({score}/100)  {details}", foreground=color)

    def _compute_strength(self, pwd):
        """Heuristique de force : longueur + diversité des caractères."""
        if not pwd:
            return 0, ""
        score = 0
        notes = []
        length = len(pwd)
        if length >= 16:   score += 40; notes.append("longueur ✓")
        elif length >= 12: score += 30; notes.append("longueur ~")
        elif length >= 8:  score += 15; notes.append("longueur !")
        else:              score +=  5; notes.append("trop court")
        if re.search(r"[A-Z]",       pwd): score += 15; notes.append("maj ✓")
        if re.search(r"[a-z]",       pwd): score += 10
        if re.search(r"[0-9]",       pwd): score += 15; notes.append("chiffre ✓")
        if re.search(r"[^A-Za-z0-9]",pwd): score += 20; notes.append("spécial ✓")
        return min(score, 100), "  ".join(notes)

    def _passwd_analyze_single(self):
        pwd = self._pwd_entry_var.get()
        if not pwd:
            messagebox.showwarning("Champ vide", "Entrez un mot de passe à analyser.")
            return
        self.btn_pwd_analyze.config(state="disabled")
        def _run():
            verdict, tag = self._run_cracklib(pwd)
            self.root.after(0, self._passwd_show_single_result, pwd, verdict, tag)
        threading.Thread(target=_run, daemon=True).start()

    def _passwd_show_single_result(self, pwd, verdict, tag):
        score, details = self._compute_strength(pwd)
        stars  = ("★" * (score // 20)).ljust(5, "☆")
        ts     = datetime.now().strftime("%H:%M:%S")
        header = f"\n{CONSOLE_SEP}\n🔑 [{ts}] Analyse du mot de passe\n"
        body   = (
            f"   Longueur   : {len(pwd)} caractères\n"
            f"   Force locale : {stars}  {details}\n"
            f"   cracklib   : {verdict}\n"
        )
        self.txt_passwd.insert(tk.END, header, "header")
        self.txt_passwd.insert(tk.END, body,   tag)
        self.txt_passwd.see(tk.END)
        self.btn_pwd_analyze.config(state="normal")

    def _run_cracklib(self, password):
        """Lance cracklib-check sur UN mot de passe. Retourne (verdict_str, tag)."""
        try:
            result  = subprocess.run(
                ["cracklib-check"],
                input=password + "\n", capture_output=True, text=True
            )
            raw     = result.stdout.strip()
            verdict = raw.split(":", 1)[-1].strip() if ":" in raw else raw
            v_lc    = verdict.lower()
            if v_lc == "ok":
                return "OK — Acceptable", "good"
            elif any(k in v_lc for k in ("too short", "trop court")):
                return f"Trop Court — {verdict}", "bad"
            elif any(k in v_lc for k in ("dictionary", "dictionn", "based on")):
                return f"Mot du Dictionnaire — {verdict}", "bad"
            elif any(k in v_lc for k in ("simple", "trivial", "weak", "too simple")):
                return f"Trop Simple — {verdict}", "warn"
            else:
                return f"Insuffisant — {verdict}", "warn"
        except FileNotFoundError:
            return "❌ cracklib-check non trouvé (sudo apt install libcrack2)", "bad"
        except Exception as e:
            return f"❌ Erreur : {e}", "bad"

    def _passwd_browse_wordlist(self):
        path = filedialog.askopenfilename(
            title="Choisir une wordlist",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous", "*")])
        if path:
            self._wl_path_var.set(path)

    def _passwd_analyze_wordlist(self):
        path = self._wl_path_var.get().strip()
        if not os.path.isfile(path):
            messagebox.showerror("Fichier introuvable", f"Impossible de trouver :\n{path}")
            return
        try:
            limit = int(self._wl_limit_var.get().strip())
            if limit <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Limite invalide", "Entrez un nombre entier positif.")
            return

        self._wl_running = True
        self.btn_wl_run.pack_forget()
        self.btn_wl_stop.pack(side="left", padx=8)
        self._wl_progress["value"] = 0
        self._wl_progress_lbl.config(text="Démarrage…")
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_passwd.insert(
            tk.END,
            f"\n{'─'*62}\n📂 [{ts}] Analyse wordlist : {path}  (max {limit} lignes)\n",
            "header"
        )
        self.txt_passwd.see(tk.END)

        def _run():
            counts = {"good": 0, "warn": 0, "bad": 0, "total": 0}
            try:
                with open(path, "r", errors="replace") as f:
                    passwords = [line.rstrip("\n") for i, line in
                                 zip(range(limit), f) if line.strip()]
            except Exception as e:
                self.root.after(0, self._passwd_wl_done,
                                f"Erreur lecture fichier : {e}", counts)
                return
            total   = len(passwords)
            results = []
            for i, pw in enumerate(passwords):
                if not self._wl_running:
                    break
                verdict, tag = self._run_cracklib(pw)
                counts["total"] += 1
                counts[tag if tag in counts else "warn"] += 1
                results.append((pw, verdict, tag))
                pct = int((i + 1) / total * 100) if total > 0 else 0
                self.root.after(0, self._passwd_wl_progress, i + 1, total, pct)
            self.root.after(0, self._passwd_wl_done_detail, results, counts)

        self._wl_thread = threading.Thread(target=_run, daemon=True)
        self._wl_thread.start()

    def _passwd_stop_wordlist(self):
        self._wl_running = False

    def _passwd_wl_progress(self, done, total, pct):
        self._wl_progress["value"] = pct
        self._wl_progress_lbl.config(text=f"{done} / {total} mots de passe analysés…")

    def _passwd_wl_done_detail(self, results, counts):
        self._wl_running = False
        self.btn_wl_stop.pack_forget()
        self.btn_wl_run.pack(side="left", padx=8)
        self._wl_progress["value"] = 100
        self._wl_progress_lbl.config(text=f"Terminé — {counts['total']} analysés.")
        ts = datetime.now().strftime("%H:%M:%S")
        summary = (
            f"── Résumé [{ts}] ──\n"
            f"   Acceptables  : {counts['good']}\n"
            f"   Insuffisants : {counts['warn']}\n"
            f"   Très faibles : {counts['bad']}\n"
            f"   Total analysés : {counts['total']}\n"
        )
        self.txt_passwd.insert(tk.END, summary, "header")
        bad_lines = [(pw, v, t) for pw, v, t in results if t in ("bad", "warn")]
        if bad_lines:
            self.txt_passwd.insert(
                tk.END, f"\n── Mots de passe faibles détectés ({len(bad_lines)}) ──\n", "header")
            for pw, verdict, tag in bad_lines[:PASSWD_WL_DISPLAY_MAX]:
                self.txt_passwd.insert(tk.END, f"   {pw:<22} {verdict}\n", tag)
        self.txt_passwd.see(tk.END)

    # =========================================================================
    #  Onglet Monitoring Système
    # =========================================================================
    def _build_tab_monitoring(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)
        self._monitoring_active   = False
        self._monitoring_after_id = None

        frame_top = ttk.Frame(tab)
        frame_top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        self.img_htop = self._load_icon("linux_Pi.png", (150, 150))
        if self.img_htop:
            ttk.Label(frame_top, image=self.img_htop).pack(side="left", padx=(0, 10))
        ttk.Label(
            frame_top,
            text="Monitoring Système – Htop & Informations",
            font=("TkDefaultFont", 12, "bold")
        ).pack(side="left", padx=5)

        frame_btns = ttk.LabelFrame(tab, text="Actions")
        frame_btns.grid(row=1, column=0, sticky="ew", padx=10, pady=4)
        self.btn_mon_start = ttk.Button(frame_btns, text="▶ Démarrer Monitoring",
                                         command=self._mon_start, style="Success.TButton")
        self.btn_mon_start.pack(side="left", padx=8, pady=6)
        self.btn_mon_stop = ttk.Button(frame_btns, text="⏹ Arrêter",
                                        command=self._mon_stop, style="Danger.TButton")
        self.btn_mon_stop.pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="📋 Infos Système",
                   command=self._mon_sysinfo, style="Info.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Espace disque",
                   command=self._mon_disk).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Interfaces réseau",
                   command=self._mon_network).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="🔍 Analyser l'espace disque",
                   command=self._mon_disk_analyze, style="Info.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="🗑 Nettoyer Système",
                   command=self._mon_clean, style="Danger.TButton"
                   ).pack(side="left", padx=8, pady=6)
        ttk.Separator(frame_btns, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)
        ttk.Button(frame_btns, text="🗑 Effacer",
                   command=lambda: self.txt_mon.delete(1.0, tk.END)
                   ).pack(side="left", padx=8, pady=6)
        ttk.Button(frame_btns, text="📋 Copier tout",
                   command=lambda: self._copy_text_widget(self.txt_mon)
                   ).pack(side="left", padx=8, pady=6)

        frame_dash = ttk.LabelFrame(tab, text="Monitoring temps réel")
        frame_dash.grid(row=2, column=0, sticky="ew", padx=10, pady=4)
        frame_dash.columnconfigure(1, weight=1)
        frame_dash.columnconfigure(3, weight=1)

        ttk.Label(frame_dash, text="CPU global :").grid(row=0, column=0, sticky="w", padx=8, pady=3)
        self.cpu_bar = ttk.Progressbar(frame_dash, length=150, maximum=100)
        self.cpu_bar.grid(row=0, column=1, sticky="ew", padx=4, pady=3)
        self.cpu_label = ttk.Label(frame_dash, text="—", width=8)
        self.cpu_label.grid(row=0, column=2, padx=4)

        ttk.Label(frame_dash, text="RAM :").grid(row=1, column=0, sticky="w", padx=8, pady=3)
        self.ram_bar = ttk.Progressbar(frame_dash, length=150, maximum=100)
        self.ram_bar.grid(row=1, column=1, sticky="ew", padx=4, pady=3)
        self.ram_label = ttk.Label(frame_dash, text="—", width=26)
        self.ram_label.grid(row=1, column=2, padx=4)

        ttk.Label(frame_dash, text="Température :").grid(
            row=0, column=3, sticky="w", padx=(40, 8), pady=3)
        self.temp_label = ttk.Label(frame_dash, text="—", font=("TkDefaultFont", 10, "bold"))
        self.temp_label.grid(row=0, column=4, padx=4, sticky="w")

        ttk.Label(frame_dash, text="Uptime :").grid(
            row=1, column=3, sticky="w", padx=(40, 8), pady=3)
        self.uptime_label = ttk.Label(frame_dash, text="—")
        self.uptime_label.grid(row=1, column=4, padx=4, sticky="w")

        ttk.Label(frame_dash, text="Charge (load) :").grid(
            row=2, column=0, sticky="w", padx=8, pady=3)
        self.load_label = ttk.Label(frame_dash, text="—")
        self.load_label.grid(row=2, column=1, columnspan=2, sticky="w", padx=4)

        frame_text = ttk.Frame(tab)
        frame_text.grid(row=3, column=0, sticky="nsew", padx=10, pady=(4, 10))
        frame_text.rowconfigure(0, weight=1)
        frame_text.columnconfigure(0, weight=1)
        self.txt_mon = scrolledtext.ScrolledText(frame_text, width=100, height=12,
                                                  font=("Courier", 9))
        self.txt_mon.grid(row=0, column=0, sticky="nsew")

    # ---- Helpers Monitoring ----

    def _append_mon(self, text, success=True):
        ts   = datetime.now().strftime("%H:%M:%S")
        icon = "✅" if success else "❌"
        self.txt_mon.insert(tk.END, f"\n{CONSOLE_SEP}\n{icon} [{ts}]\n{text.rstrip()}\n")
        self.txt_mon.see(tk.END)

    def _mon_start(self):
        self._monitoring_active = True
        self._mon_refresh()

    def _mon_stop(self):
        self._monitoring_active = False
        if self._monitoring_after_id:
            self.root.after_cancel(self._monitoring_after_id)
            self._monitoring_after_id = None

    def _mon_refresh(self):
        if not self._monitoring_active:
            return
        try:
            import psutil
            cpu_pct = psutil.cpu_percent(interval=None)
            self.cpu_bar["value"] = cpu_pct
            self.cpu_label.config(text=f"{cpu_pct:.1f}%")

            mem      = psutil.virtual_memory()
            used_mb  = mem.used  // (1024 * 1024)
            total_mb = mem.total // (1024 * 1024)
            self.ram_bar["value"] = mem.percent
            self.ram_label.config(
                text=f"{used_mb} Mo / {total_mb} Mo ({mem.percent:.0f}%)")

            try:
                temp = int(
                    Path("/sys/class/thermal/thermal_zone0/temp").read_text().strip()
                ) / 1000
                color = ("#cc0000" if temp > TEMP_CRIT_THRESHOLD
                         else "#cc6600" if temp > TEMP_WARN_THRESHOLD
                         else "#007700")
                self.temp_label.config(text=f"{temp:.1f} °C", foreground=color)
            except Exception:
                self.temp_label.config(text="N/A")

            uptime_s = int(time.time() - psutil.boot_time())
            h, r = divmod(uptime_s, 3600)
            m, s = divmod(r, 60)
            self.uptime_label.config(text=f"{h}h {m}m {s}s")

            la = psutil.getloadavg()
            self.load_label.config(text=f"{la[0]:.2f}  {la[1]:.2f}  {la[2]:.2f}  (1m 5m 15m)")

            procs = sorted(
                psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]),
                key=lambda p: p.info["cpu_percent"] or 0, reverse=True
            )[:MONITORING_TOP_N]
            lines = [f"{'PID':>6}  {'CPU%':>6}  {'MEM%':>6}  NOM"]
            lines += [
                f"{p.info['pid']:>6}  {p.info['cpu_percent'] or 0:>6.1f}  "
                f"{p.info['memory_percent'] or 0:>6.1f}  {p.info['name']}"
                for p in procs
            ]
            self.txt_mon.delete(1.0, tk.END)
            self.txt_mon.insert(tk.END,
                f"── Top {MONITORING_TOP_N} processus ──\n" + "\n".join(lines))

        except ImportError:
            self.txt_mon.delete(1.0, tk.END)
            self.txt_mon.insert(
                tk.END,
                "psutil non installé.\n"
                "Installez-le : pip install psutil --break-system-packages\n"
            )
            self._monitoring_active = False
            return
        except Exception as e:
            self.txt_mon.insert(tk.END, f"\nErreur monitoring : {e}\n")

        self._monitoring_after_id = self.root.after(MONITORING_INTERVAL_MS, self._mon_refresh)

    def _mon_sysinfo(self):
        def _get():
            lines = []
            for cmd, label in [
                (["uname", "-a"],      "── uname -a ──"),
                (["lsb_release", "-a"],"── lsb_release -a ──"),
                (["hostnamectl"],       "── hostnamectl ──"),
                (["lscpu"],            "── lscpu ──"),
                (["free", "-m"],       "── free -m ──"),
            ]:
                result = subprocess.run(cmd, capture_output=True, text=True)
                out    = (result.stdout + result.stderr).strip()
                lines.append(f"{label}\n{out}")
            self.root.after(0, self._append_mon, "\n\n".join(lines), True)
        threading.Thread(target=_get, daemon=True).start()

    def _mon_disk(self):
        def _get():
            lines = []
            for cmd, label in [
                (["df", "-h"],  "── df -h (espace disque) ──"),
                (["lsblk"],     "── lsblk (périphériques) ──"),
            ]:
                result = subprocess.run(cmd, capture_output=True, text=True)
                out    = (result.stdout + result.stderr).strip()
                lines.append(f"{label}\n{out}")
            self.root.after(0, self._append_mon, "\n\n".join(lines), True)
        threading.Thread(target=_get, daemon=True).start()

    def _mon_network(self):
        def _get():
            result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
            ok     = result.returncode == 0
            out    = (result.stdout + result.stderr).strip()
            self.root.after(0, self._append_mon, "── ip addr ──\n" + out, ok)
        threading.Thread(target=_get, daemon=True).start()

    # ---- Helper : taille lisible (o / Ko / Mo / Go / To) ----
    def _human_size(self, num_bytes):
        size = float(num_bytes)
        for unit in ["o", "Ko", "Mo", "Go", "To"]:
            if abs(size) < 1024.0:
                return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} Po"

    # =========================================================================
    #  Analyse d'espace disque (façon ncdu) — Top N dossiers les plus volumineux
    # =========================================================================
    def _mon_disk_analyze(self):
        self._append_mon(
            f"Analyse de l'espace disque en cours (du -x -d {DISK_ANALYZE_DEPTH} "
            f"{DISK_ANALYZE_ROOT})...\nCela peut prendre du temps selon la taille du disque.",
            True
        )

        def _scan():
            shell_cmd = (
                f"du -x -d {DISK_ANALYZE_DEPTH} {DISK_ANALYZE_ROOT} 2>/dev/null "
                f"| sort -rn | head -n {DISK_ANALYZE_TOP_N}"
            )
            result = subprocess.run(["sudo", "sh", "-c", shell_cmd],
                                     capture_output=True, text=True)
            ok = result.returncode == 0

            entries = []
            for line in result.stdout.splitlines():
                parts = line.split("\t", 1)
                if len(parts) != 2:
                    continue
                try:
                    size_kb = int(parts[0])
                except ValueError:
                    continue
                entries.append((size_kb, parts[1]))

            if not entries:
                self.root.after(0, self._append_mon,
                    "Aucun résultat exploitable (droits insuffisants ou 'du' indisponible).",
                    False)
                return

            body = [f"── Top {len(entries)} dossiers les plus volumineux "
                    f"(sous {DISK_ANALYZE_ROOT}, profondeur {DISK_ANALYZE_DEPTH}, "
                    f"même système de fichiers) ──"]
            for size_kb, path in entries:
                body.append(f"{self._human_size(size_kb * 1024):>10}   {path}")
            body.append("")
            body.append("💡 Pour explorer interactivement : sudo ncdu -x " + DISK_ANALYZE_ROOT)
            self.root.after(0, self._append_mon, "\n".join(body), ok)

        threading.Thread(target=_scan, daemon=True).start()

    # =========================================================================
    #  Nettoyage système — sélection des éléments, aperçu, bilan avant/après
    # =========================================================================
    def _mon_clean(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Nettoyer le système")
        dialog.resizable(False, False)

        ttk.Label(dialog, text="Sélectionnez les éléments à nettoyer :",
                  font=("TkDefaultFont", 10, "bold")
                  ).grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(12, 6))

        self._clean_apt_var      = tk.BooleanVar(value=True)
        self._clean_tmp_var      = tk.BooleanVar(value=True)
        self._clean_journal_var  = tk.BooleanVar(value=False)
        self._clean_pipcache_var = tk.BooleanVar(value=False)
        self._clean_thumbs_var   = tk.BooleanVar(value=False)
        self._clean_docker_var   = tk.BooleanVar(value=False)
        docker_present = shutil.which("docker") is not None

        ttk.Checkbutton(dialog, text="Paquets APT obsolètes (autoremove --purge, autoclean, clean)",
                         variable=self._clean_apt_var
                         ).grid(row=1, column=0, columnspan=2, sticky="w", padx=14, pady=2)
        ttk.Checkbutton(dialog, text="Fichiers temporaires (/tmp, /var/tmp)",
                         variable=self._clean_tmp_var
                         ).grid(row=2, column=0, columnspan=2, sticky="w", padx=14, pady=2)

        row_journal = ttk.Frame(dialog)
        row_journal.grid(row=3, column=0, columnspan=2, sticky="w", padx=14, pady=2)
        ttk.Checkbutton(row_journal, text="Journaux systemd — conserver les",
                         variable=self._clean_journal_var).pack(side="left")
        self._clean_journal_days = tk.StringVar(value="7")
        ttk.Entry(row_journal, textvariable=self._clean_journal_days, width=4
                   ).pack(side="left", padx=4)
        ttk.Label(row_journal, text="derniers jours").pack(side="left")

        ttk.Checkbutton(dialog, text="Cache pip (~/.cache/pip)",
                         variable=self._clean_pipcache_var
                         ).grid(row=4, column=0, columnspan=2, sticky="w", padx=14, pady=2)
        ttk.Checkbutton(dialog, text="Cache miniatures (~/.cache/thumbnails)",
                         variable=self._clean_thumbs_var
                         ).grid(row=5, column=0, columnspan=2, sticky="w", padx=14, pady=2)
        next_row = 6
        if docker_present:
            ttk.Checkbutton(dialog,
                text="Docker : images/conteneurs/volumes inutilisés (system prune)",
                variable=self._clean_docker_var
                ).grid(row=next_row, column=0, columnspan=2, sticky="w", padx=14, pady=2)
            next_row += 1

        preview = scrolledtext.ScrolledText(dialog, width=78, height=8, font=("Courier", 8))
        preview.grid(row=next_row, column=0, columnspan=2, padx=14, pady=(8, 6))
        preview.insert(tk.END, "⏳ Analyse en cours, merci de patienter...")
        preview.configure(state="disabled")
        next_row += 1

        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=next_row, column=0, columnspan=2, pady=12)
        btn_launch = ttk.Button(btn_frame, text="🗑 Lancer le nettoyage",
                                 style="Danger.TButton", state="disabled")
        btn_launch.pack(side="left", padx=8)
        ttk.Button(btn_frame, text="Annuler", command=dialog.destroy).pack(side="left", padx=8)

        def _set_preview(text):
            preview.configure(state="normal")
            preview.delete(1.0, tk.END)
            preview.insert(tk.END, text)
            preview.configure(state="disabled")
            btn_launch.configure(state="normal")

        def _load_preview():
            apt_res = subprocess.run(["apt-get", "--dry-run", "autoremove"],
                                      capture_output=True, text=True)
            journal_res = subprocess.run(["journalctl", "--disk-usage"],
                                          capture_output=True, text=True)
            apt_out = (apt_res.stdout + apt_res.stderr)
            noise_keywords = [
                "note :", "note:", "simulation", "superutilisateur",
                "privilège", "privilege", "verrouillage", "locking is",
                "lock is not held", "réalité", "reality", "représentative",
                "vraiment fonctionner", "real execution", "uninteresting",
            ]
            apt_lines = [
                line for line in apt_out.splitlines()
                if not any(kw in line.lower() for kw in noise_keywords)
            ]
            apt_out = "\n".join(apt_lines).strip()

            text = "── apt-get --dry-run autoremove ──\n"
            text += apt_out or "(aucune sortie)"
            text += "\n\n── journalctl --disk-usage ──\n"
            text += (journal_res.stdout + journal_res.stderr).strip() or "(indisponible)"
            self.root.after(0, _set_preview, text)

        threading.Thread(target=_load_preview, daemon=True).start()

        def _launch():
            if not messagebox.askyesno(
                "Confirmation",
                "Lancer le nettoyage avec les éléments cochés ?\n"
                "Cette action est irréversible."
            ):
                return
            selection = {
                "apt": self._clean_apt_var.get(),
                "tmp": self._clean_tmp_var.get(),
                "journal": self._clean_journal_var.get(),
                "journal_days": self._clean_journal_days.get().strip() or "7",
                "pip": self._clean_pipcache_var.get(),
                "thumbs": self._clean_thumbs_var.get(),
                "docker": self._clean_docker_var.get(),
            }
            dialog.destroy()
            self._mon_clean_run(selection)

        btn_launch.configure(command=_launch)

    def _mon_clean_run(self, selection):
        self._append_mon("Nettoyage du système en cours...", True)
        pip_cache_dir  = Path.home() / ".cache" / "pip"
        thumbs_dir     = Path.home() / ".cache" / "thumbnails"

        def _clean():
            usage_before = shutil.disk_usage("/")
            cmds = []

            if selection["apt"]:
                cmds += [
                    (["sudo", "apt", "autoremove", "--purge", "-y"], "apt autoremove --purge"),
                    (["sudo", "apt", "autoclean"],                    "apt autoclean"),
                    (["sudo", "apt", "clean"],                        "apt clean"),
                ]
            if selection["tmp"]:
                cmds += [
                    (["sudo", "sh", "-c", "rm -rf /tmp/*"],     "rm /tmp/*"),
                    (["sudo", "sh", "-c", "rm -rf /var/tmp/*"], "rm /var/tmp/*"),
                ]
            if selection["journal"]:
                days = selection["journal_days"]
                cmds.append((["sudo", "journalctl", f"--vacuum-time={days}d"],
                              f"journalctl --vacuum-time={days}d"))
            if selection["pip"]:
                cmds.append((["rm", "-rf", str(pip_cache_dir)], "purge cache pip"))
            if selection["thumbs"]:
                cmds.append((["rm", "-rf", str(thumbs_dir)], "purge cache miniatures"))
            if selection["docker"]:
                cmds.append((["sudo", "docker", "system", "prune", "-f"],
                              "docker system prune"))

            results = []
            for cmd, label in cmds:
                result = subprocess.run(cmd, capture_output=True, text=True)
                out    = (result.stdout + result.stderr).strip()
                ok     = result.returncode == 0
                results.append(f"{'✅' if ok else '❌'} {label}\n{out}")

            usage_after = shutil.disk_usage("/")
            freed = usage_after.free - usage_before.free

            summary = (
                f"💾 Espace disque libéré : {self._human_size(max(freed, 0))}\n"
                f"   Avant : {self._human_size(usage_before.free)} libres  →  "
                f"Après : {self._human_size(usage_after.free)} libres"
            )
            report = summary + "\n\n" + "\n\n".join(results) if results else summary + \
                "\n\n(aucun élément sélectionné)"
            self.root.after(0, self._append_mon, report, True)

        threading.Thread(target=_clean, daemon=True).start()

# =============================================================================
#  main
# =============================================================================
def main():
    root = tk.Tk()
    root.withdraw()
    splash = SplashScreen(root, str(ICON_DIR / SPLASH_IMAGE_NAME))

    def show_main():
        splash.close()
        root.deiconify()
        SecurityGUI(root)

    root.after(SPLASH_DURATION_MS, show_main)
    root.mainloop()


if __name__ == "__main__":
    main()
