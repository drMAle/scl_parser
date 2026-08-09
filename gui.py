import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

from scl_parser import SCLModel
from analyzer import Analyzer
from version import APP_NAME, VERSION, AUTHOR


class SCLAnalyzerApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            f"{APP_NAME} {VERSION}"
        )

        self.root.geometry(
            "1100x650"
        )

        self.root.minsize(
            800,
            500
        )

        self.current_file = None
        self.issues = []

        self.create_menu()
        self.create_widgets()

    # =========================================================
    # MENU
    # =========================================================

    def create_menu(self):

        menubar = tk.Menu(
            self.root
        )

        # -----------------------------------------------------
        # File
        # -----------------------------------------------------

        file_menu = tk.Menu(
            menubar,
            tearoff=False
        )

        file_menu.add_command(
            label="Open",
            command=self.open_file
        )

        file_menu.add_separator()

        file_menu.add_command(
            label="Exit",
            command=self.root.quit
        )

        menubar.add_cascade(
            label="File",
            menu=file_menu
        )

        # -----------------------------------------------------
        # Options
        # -----------------------------------------------------

        options_menu = tk.Menu(
            menubar,
            tearoff=False
        )

        self.cei016_enabled = tk.BooleanVar(
            value=True 
        ) 
        
        options_menu.add_checkbutton(
            label="CEI 0-16 checks", 
            variable=self.cei016_enabled
        )

        menubar.add_cascade(
            label="Options",
            menu=options_menu
        )

        # -----------------------------------------------------
        # Help
        # -----------------------------------------------------

        help_menu = tk.Menu(
            menubar,
            tearoff=False
        )

        help_menu.add_command(
            label="About",
            command=self.show_about
        )

        menubar.add_cascade(
            label="Help",
            menu=help_menu
        )

        self.root.config(
            menu=menubar
        )

    # =========================================================
    # GUI
    # =========================================================

    def create_widgets(self):

        main = ttk.Frame(
            self.root,
            padding=10
        )

        main.pack(
            fill=tk.BOTH,
            expand=True
        )

        # -----------------------------------------------------
        # File information
        # -----------------------------------------------------

        file_frame = ttk.Frame(main)

        file_frame.pack(
            fill=tk.X,
            pady=(0, 8)
        )

        ttk.Label(
            file_frame,
            text="SCL file:"
        ).pack(
            side=tk.LEFT
        )

        self.file_label = ttk.Label(
            file_frame,
            text="No file selected"
        )

        self.file_label.pack(
            side=tk.LEFT,
            padx=10
        )

        # -----------------------------------------------------
        # Summary
        # -----------------------------------------------------

        summary = ttk.Frame(main)

        summary.pack(
            fill=tk.X,
            pady=(0, 8)
        )

        self.summary_label = ttk.Label(
            summary,
            text="No analysis performed"
        )

        self.summary_label.pack(
            side=tk.LEFT
        )

        # -----------------------------------------------------
        # Treeview
        # -----------------------------------------------------

        table_frame = ttk.Frame(main)

        table_frame.pack(
            fill=tk.BOTH,
            expand=True
        )

        columns = (
            "severity",
            "rule",
            "ied",
            "location",
            "description"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        self.tree.heading(
            "severity",
            text="Severity"
        )

        self.tree.heading(
            "rule",
            text="Rule"
        )

        self.tree.heading(
            "ied",
            text="IED"
        )

        self.tree.heading(
            "location",
            text="Location"
        )

        self.tree.heading(
            "description",
            text="Description"
        )

        self.tree.column(
            "severity",
            width=90,
            anchor=tk.CENTER
        )

        self.tree.column(
            "rule",
            width=90,
            anchor=tk.CENTER
        )

        self.tree.column(
            "ied",
            width=150
        )

        self.tree.column(
            "location",
            width=300
        )

        self.tree.column(
            "description",
            width=450
        )

        scrollbar_y = ttk.Scrollbar(
            table_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview
        )

        scrollbar_x = ttk.Scrollbar(
            table_frame,
            orient=tk.HORIZONTAL,
            command=self.tree.xview
        )

        self.tree.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        scrollbar_y.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        scrollbar_x.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.grid_rowconfigure(
            0,
            weight=1
        )

        table_frame.grid_columnconfigure(
            0,
            weight=1
        )

        # -----------------------------------------------------
        # Tags
        # -----------------------------------------------------

        self.tree.tag_configure(
            "ERROR",
            foreground="red"
        )

        self.tree.tag_configure(
            "WARNING",
            foreground="orange"
        )

        self.tree.tag_configure(
            "INFO",
            foreground="blue"
        )

        # -----------------------------------------------------
        # Status bar
        # -----------------------------------------------------

        self.status_label = ttk.Label(
            self.root,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W
        )

        self.status_label.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )

    # =========================================================
    # OPEN
    # =========================================================

    def open_file(self):

        filename = filedialog.askopenfilename(
            title="Open SCL file",
            filetypes=[
                ("ICD files", "*.icd"),
                ("CID files", "*.cid"),
                ("SCD files", "*.scd"),
                ("SCL files", "*.scl"),
                ("All files", "*.*")
            ]
        )

        if not filename:
            return

        self.current_file = Path(filename)

        self.file_label.config(
            text=str(self.current_file)
        )

        self.clear_results()

        self.status_label.config(
            text="Analyzing..."
        )

        self.root.update_idletasks()

        try:

            model = SCLModel(
                self.current_file
            )

            model.load()

            analyzer = Analyzer(
                model,
                cei016_enabled=self.cei016_enabled.get()
            )

            self.issues = analyzer.run()

            self.display_results()

            self.status_label.config(
                text="Analysis completed"
            )

            # -----------------------------------------------------
            # Analysis summary popup
            # -----------------------------------------------------

            errors = sum(
                1
                for issue in self.issues
                if issue.severity == "ERROR"
            )

            warnings = sum(
                1
                for issue in self.issues
                if issue.severity == "WARNING"
            )

            if errors == 0 and warnings == 0:

                messagebox.showinfo(
                    "Analysis completed",
                    "Parsing completed: No errors found."
                )

            elif errors == 0:

                messagebox.showwarning(
                    "Analysis completed",
                    f"Parsing completed: No errors found.\n"
                    f"However, {warnings} warning(s) were detected.\n\n"
                    f"Please check the warning list."
                )

            else:

                messagebox.showerror(
                    "Analysis completed",
                    f"Parsing completed: {errors} error(s) found.\n\n"
                    f"Please check the error list."
                )

        except Exception as exc:

            self.status_label.config(
                text="Analysis failed"
            )

            messagebox.showerror(
                "Analysis Error",
                str(exc)
            )

    # =========================================================
    # DISPLAY RESULTS
    # =========================================================

    def clear_results(self):

        for item in self.tree.get_children():

            self.tree.delete(item)

    def display_results(self):

        self.clear_results()

        errors = 0
        warnings = 0
        infos = 0

        for issue in self.issues:

            if issue.severity == "ERROR":
                errors += 1

            elif issue.severity == "WARNING":
                warnings += 1

            elif issue.severity == "INFO":
                infos += 1

            self.tree.insert(
                "",
                tk.END,
                values=issue.as_tuple(),
                tags=(issue.severity,)
            )

        self.summary_label.config(
            text=(
                f"Errors: {errors}    "
                f"Warnings: {warnings}    "
                f"Info: {infos}    "
                f"Total: {len(self.issues)}"
            )
        )

    # =========================================================
    # ABOUT
    # =========================================================

    def show_about(self):

        dialog = tk.Toplevel(
            self.root
        )

        dialog.title(
            "About"
        )

        dialog.geometry(
            "350x180"
        )

        dialog.resizable(
            False,
            False
        )

        dialog.transient(
            self.root
        )

        dialog.grab_set()

        frame = ttk.Frame(
            dialog,
            padding=20
        )

        frame.pack(
            fill=tk.BOTH,
            expand=True
        )

        ttk.Label(
            frame,
            text=APP_NAME,
            font=(
                "TkDefaultFont",
                14,
                "bold"
            )
        ).pack(
            pady=(0, 10)
        )

        ttk.Label(
            frame,
            text=f"Version {VERSION}"
        ).pack()

        ttk.Label(
            frame,
            text=f"Author: {AUTHOR}"
        ).pack(
            pady=(5, 15)
        )

        ttk.Button(
            frame,
            text="OK",
            width=10,
            command=dialog.destroy
        ).pack()

        dialog.bind(
            "<Return>",
            lambda event: dialog.destroy()
        )

        dialog.bind(
            "<Escape>",
            lambda event: dialog.destroy()
        )
