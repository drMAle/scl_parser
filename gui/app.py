import tkinter as tk
from tkinter import ttk,filedialog,messagebox
from pathlib import Path
from model import SCLModel,PcapModel
from analyzer import Analyzer
from comparison import compare_models
from version import APP_NAME,VERSION,AUTHOR

class SCLAnalyzerApp:
    def __init__(self,root):
        self.root=root; root.title(f'{APP_NAME} {VERSION}'); root.geometry('1100x650'); root.minsize(800,500)
        self.current_file=None; self.issues=[]; self.current_model=None; self.create_menu(); self.create_widgets()
    def create_menu(self):
        mb=tk.Menu(self.root); fm=tk.Menu(mb,tearoff=False); fm.add_command(label='Open SCL',command=self.open_scl); fm.add_command(label='Open PCAP',command=self.open_pcap); fm.add_command(label='Compare SCL and PCAP',command=self.compare_scl_pcap); fm.add_separator(); fm.add_command(label='Check default values in PCAP',command=self.check_default_values); fm.add_separator(); fm.add_command(label='Exit',command=self.root.quit); mb.add_cascade(label='File',menu=fm)
        om=tk.Menu(mb,tearoff=False); self.iec61850_enabled=tk.BooleanVar(value=True); self.cei016_enabled=tk.BooleanVar(value=True); om.add_checkbutton(label='IEC 61850 checks',variable=self.iec61850_enabled); om.add_checkbutton(label='CEI 0-16 checks',variable=self.cei016_enabled); mb.add_cascade(label='Options',menu=om)
        hm=tk.Menu(mb,tearoff=False); hm.add_command(label='About',command=self.show_about); mb.add_cascade(label='Help',menu=hm); self.root.config(menu=mb)
    def create_widgets(self):
        main=ttk.Frame(self.root,padding=10); main.pack(fill=tk.BOTH,expand=True)
        top=ttk.Frame(main); top.pack(fill=tk.X,pady=(0,8)); ttk.Label(top,text='Input:').pack(side=tk.LEFT); self.file_label=ttk.Label(top,text='No file selected'); self.file_label.pack(side=tk.LEFT,padx=10)
        self.summary_label=ttk.Label(main,text='No analysis performed'); self.summary_label.pack(fill=tk.X,pady=(0,8))
        tf=ttk.Frame(main); tf.pack(fill=tk.BOTH,expand=True); cols=('severity','rule','ied','location','description'); self.tree=ttk.Treeview(tf,columns=cols,show='headings')
        for c,t in zip(cols,('Severity','Rule','IED','Location','Description')): self.tree.heading(c,text=t)
        for c,w in zip(cols,(90,110,150,300,450)): self.tree.column(c,width=w,anchor=tk.CENTER if c in ('severity','rule') else tk.W)
        sy=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.tree.yview); sx=ttk.Scrollbar(tf,orient=tk.HORIZONTAL,command=self.tree.xview); self.tree.configure(yscrollcommand=sy.set,xscrollcommand=sx.set); self.tree.grid(row=0,column=0,sticky='nsew'); sy.grid(row=0,column=1,sticky='ns'); sx.grid(row=1,column=0,sticky='ew'); tf.grid_rowconfigure(0,weight=1); tf.grid_columnconfigure(0,weight=1)
        self.tree.tag_configure('ERROR',foreground='red'); self.tree.tag_configure('WARNING',foreground='orange'); self.tree.tag_configure('INFO',foreground='blue')
        self.status_label=ttk.Label(self.root,text='Ready',relief=tk.SUNKEN,anchor=tk.W); self.status_label.pack(side=tk.BOTTOM,fill=tk.X)
    def _analyze_model(self,model):
        analyzer=Analyzer(model,self.iec61850_enabled.get(),self.cei016_enabled.get()); return analyzer.run()
    def open_path(self, path, kind):
        self.current_file=Path(path); self.file_label.config(text=str(self.current_file)); self.clear_results(); self.status_label.config(text='Analyzing...'); self.root.update_idletasks()
        try:
            model=(SCLModel if kind=='scl' else PcapModel)(self.current_file).load(); self.current_model=model
            self.issues=self._analyze_model(model); self.display_results(); self.status_label.config(text='Analysis completed'); self._summary('Analysis completed')
        except Exception as exc:
            self.status_label.config(text='Analysis failed'); messagebox.showerror('Analysis Error',str(exc))

    def _open(self,kind):
        if kind=='scl': types=[('SCL files','*.cid *.icd *.scd *.scl'),('All files','*.*')]; title='Open SCL file'
        else: types=[('Capture files','*.pcap *.pcapng'),('All files','*.*')]; title='Open PCAP capture'
        filename=filedialog.askopenfilename(title=title,filetypes=types)
        if not filename:return
        self.open_path(filename, kind)
    def open_scl(self): self._open('scl')
    def open_pcap(self): self._open('pcap')
    def check_default_values(self):
        filename=filedialog.askopenfilename(title='Select PCAP capture',filetypes=[('Capture files','*.pcap *.pcapng'),('All files','*.*')])
        if not filename:return
        self.clear_results(); self.current_file=Path(filename); self.file_label.config(text=str(self.current_file)); self.status_label.config(text='Checking default values...'); self.root.update_idletasks()
        try:
            model=PcapModel(self.current_file).load()
            from rules.iec61850.default_values import check_default_values
            self.current_model=model; self.issues=check_default_values(model); self.display_results(); self.status_label.config(text='Default-value check completed'); self._summary('Default-value check')
        except Exception as exc:
            self.status_label.config(text='Default-value check failed'); messagebox.showerror('Default-value Check Error',str(exc))
    def compare_scl_pcap(self):
        sf=filedialog.askopenfilename(title='Select SCL file',filetypes=[('SCL files','*.cid *.icd *.scd *.scl'),('All files','*.*')]);
        if not sf:return
        pf=filedialog.askopenfilename(title='Select PCAP capture',filetypes=[('Capture files','*.pcap *.pcapng'),('All files','*.*')]);
        if not pf:return
        try:
            sm=SCLModel(sf).load(); pm=PcapModel(pf).load(); self.current_model=pm; self.file_label.config(text=f'SCL: {sf} | PCAP: {pf}'); self.issues=compare_models(sm,pm); self.display_results(); self._summary('Comparison completed'); self.status_label.config(text='Comparison completed')
        except Exception as exc: messagebox.showerror('Comparison Error',str(exc))
    def clear_results(self):
        for x in self.tree.get_children(): self.tree.delete(x)
    def display_results(self):
        self.clear_results(); counts={'ERROR':0,'WARNING':0,'INFO':0}
        for issue in self.issues: counts[issue.severity]=counts.get(issue.severity,0)+1; self.tree.insert('',tk.END,values=issue.as_tuple(),tags=(issue.severity,))
        self.summary_label.config(text=f"Errors: {counts.get('ERROR',0)}    Warnings: {counts.get('WARNING',0)}    Info: {counts.get('INFO',0)}    Total: {len(self.issues)}")
    def _summary(self,title):
        e=sum(i.severity=='ERROR' for i in self.issues); w=sum(i.severity=='WARNING' for i in self.issues)
        if e==0 and w==0: messagebox.showinfo(title,'Analysis completed: No errors found.')
        elif e==0: messagebox.showwarning(title,f'Analysis completed: No errors found.\nHowever, {w} warning(s) were detected.')
        else: messagebox.showerror(title,f'Analysis completed: {e} error(s) found.\nPlease check the error list.')
    def show_about(self):
        d=tk.Toplevel(self.root); d.title('About'); d.geometry('350x180'); d.resizable(False,False); d.transient(self.root); ttk.Label(d,text=APP_NAME,font=('TkDefaultFont',14,'bold')).pack(pady=(25,10)); ttk.Label(d,text=f'Version {VERSION}').pack(); ttk.Label(d,text=f'Author: {AUTHOR}').pack(pady=5); ttk.Button(d,text='OK',command=d.destroy).pack(pady=10)
