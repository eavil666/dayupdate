#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI 界面层（方案一拆分）
功能：tkinter 主界面（文件选择/业务IP导入/终端IP表导入/日期/总结/跟进/情报/日志/进度/更新检查）。
依赖：common（路径/回调注册）、ipdb（业务IP/终端IP表/IP报告）、report（自动识别/日报）、updater（更新）。
注意：版本号通过 gui_main(app_version) 参数注入，避免 main↔gui 循环 import。
"""

import os
import re
import threading
from pathlib import Path
from datetime import datetime
from tkinter import (
    Tk, Frame, Label, Button, Listbox, Entry, Text,
    Scrollbar, filedialog, messagebox, StringVar, END, NONE,
    DISABLED, NORMAL
)

from common import runtime_dir, set_gui_callbacks
from ipdb import (load_external_excluded_ips, set_terminal_ip_table_path,
                  load_terminal_ip_table, generate_ip_report)
from report import pick_input_and_date, generate_daily_report
from updater import AutoUpdater, load_update_config


# GUI 文本框示例占位文本
EXAMPLE_WORK_SUMMARY = '示例：\n1. 完成防火墙规则优化\n2. 处置高危漏洞告警'
EXAMPLE_INTEL_ITEMS = '示例：\n1. CVE-2024-XXXX 高危漏洞，需尽快修复\n2. 新发现XX行业专项攻击预警'


class DailyReportGUI:
    def __init__(self, master, app_version='1.5.0'):
        self.master = master
        self.app_version = app_version
        master.title('网络安全值守保障日报')
        master.geometry('850x750')
        master.resizable(False, False)

        self.input_files = []
        self.date_var = StringVar(value=datetime.now().strftime('%Y%m%d'))

        # 注册全局日志回调（common.set_gui_callbacks）
        set_gui_callbacks(self._log, self._set_progress)

        self._build_ui()

        # 启动时后台自动检查更新（静默模式，不打扰用户）
        threading.Thread(target=self._check_update_startup, daemon=True).start()

    def _build_ui(self):
        # 顶部标题
        title_frame = Frame(self.master, padx=10, pady=5)
        title_frame.pack(fill='x')
        Label(title_frame, text='网络安全值守保障日报', font=('宋体', 16, 'bold')).pack(side='left')
        Label(title_frame, text=f'v{self.app_version}', font=('宋体', 9), fg='#666666').pack(side='left', padx=(10, 0))
        Button(title_frame, text='检查更新', command=self._check_update_manual, width=10,
               font=('宋体', 9)).pack(side='right')

        # 文件选择区域
        file_frame = Frame(self.master, padx=10, pady=5)
        file_frame.pack(fill='x')

        Label(file_frame, text='输入文件:', font=('宋体', 10)).pack(anchor='w')

        btn_frame = Frame(file_frame)
        btn_frame.pack(fill='x', pady=2)

        Button(btn_frame, text='选择文件', command=self._select_files, width=15,
               font=('宋体', 10)).pack(side='left')
        Button(btn_frame, text='自动识别', command=self._auto_detect, width=15,
               font=('宋体', 10)).pack(side='left', padx=5)
        Button(btn_frame, text='清空列表', command=self._clear_files, width=15,
               font=('宋体', 10)).pack(side='right')

        # 文件列表
        list_frame = Frame(file_frame)
        list_frame.pack(fill='x', pady=2)

        scrollbar = Scrollbar(list_frame, orient='vertical')
        self.file_listbox = Listbox(list_frame, yscrollcommand=scrollbar.set,
                                    font=('宋体', 9), selectmode='extended', height=5)
        scrollbar.config(command=self.file_listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self.file_listbox.pack(side='left', fill='x', expand=True)

        # IP导入区域（业务IP + 终端IP表 并列一行）
        ip_import_frame = Frame(self.master, padx=10, pady=3)
        ip_import_frame.pack(fill='x')

        self.excluded_ip_label_var = StringVar(value='未导入')
        Button(ip_import_frame, text='导入业务IP', command=self._load_biz_ips, width=12,
               font=('宋体', 10)).pack(side='left')
        Label(ip_import_frame, textvariable=self.excluded_ip_label_var,
              font=('宋体', 9), fg='gray').pack(side='left', padx=(3, 15))

        self.terminal_ip_label_var = StringVar(value='未导入')
        Button(ip_import_frame, text='导入终端IP表', command=self._load_terminal_ips, width=14,
               font=('宋体', 10)).pack(side='left')
        Label(ip_import_frame, textvariable=self.terminal_ip_label_var,
              font=('宋体', 9), fg='gray').pack(side='left', padx=5)

        # 日期输入
        date_frame = Frame(self.master, padx=10, pady=3)
        date_frame.pack(fill='x')

        Label(date_frame, text='日期:', font=('宋体', 10)).pack(side='left')
        Entry(date_frame, textvariable=self.date_var, width=12,
              font=('宋体', 10)).pack(side='left', padx=5)

        # 重点工作总结输入区域
        work_frame = Frame(self.master, padx=10, pady=3)
        work_frame.pack(fill='x')

        Label(work_frame, text='重点工作总结（每行一项）:', font=('宋体', 10)).pack(anchor='w')
        work_inner = Frame(work_frame)
        work_inner.pack(fill='x')
        work_scroll = Scrollbar(work_inner, orient='vertical')
        self.work_summary_text = Text(work_inner, font=('宋体', 10),
                                      yscrollcommand=work_scroll.set,
                                      height=3, wrap='word')
        work_scroll.config(command=self.work_summary_text.yview)
        work_scroll.pack(side='right', fill='y')
        self.work_summary_text.pack(side='left', fill='x', expand=True)
        self.work_summary_text.insert(END, '示例：\n1. 完成防火墙规则优化\n2. 处置高危漏洞告警')

        # 待跟进事项输入区域
        follow_frame = Frame(self.master, padx=10, pady=3)
        follow_frame.pack(fill='x')

        Label(follow_frame, text='待跟进事项（每行一项，不填则使用默认）:', font=('宋体', 10)).pack(anchor='w')
        follow_inner = Frame(follow_frame)
        follow_inner.pack(fill='x')
        follow_scroll = Scrollbar(follow_inner, orient='vertical')
        self.follow_items_text = Text(follow_inner, font=('宋体', 10),
                                       yscrollcommand=follow_scroll.set,
                                       height=3, wrap='word')
        follow_scroll.config(command=self.follow_items_text.yview)
        follow_scroll.pack(side='right', fill='y')
        self.follow_items_text.pack(side='left', fill='x', expand=True)

        # 情报动态输入区域
        intel_frame = Frame(self.master, padx=10, pady=3)
        intel_frame.pack(fill='x')

        Label(intel_frame, text='情报动态（每行一项，不填则使用默认表格）:', font=('宋体', 10)).pack(anchor='w')
        intel_inner = Frame(intel_frame)
        intel_inner.pack(fill='x')
        intel_scroll = Scrollbar(intel_inner, orient='vertical')
        self.intel_items_text = Text(intel_inner, font=('宋体', 10),
                                      yscrollcommand=intel_scroll.set,
                                      height=3, wrap='word')
        intel_scroll.config(command=self.intel_items_text.yview)
        intel_scroll.pack(side='right', fill='y')
        self.intel_items_text.pack(side='left', fill='x', expand=True)
        self.intel_items_text.insert(END, '示例：\n1. CVE-2024-XXXX 高危漏洞，需尽快修复\n2. 新发现XX行业专项攻击预警')

        # 日志输出区域
        log_frame = Frame(self.master, padx=10, pady=2)
        log_frame.pack(fill='x')

        Label(log_frame, text='执行日志:', font=('宋体', 10)).pack(anchor='w')

        log_inner = Frame(log_frame, height=100)
        log_inner.pack(fill='x', pady=2)
        log_inner.pack_propagate(False)

        self.log_text = Text(log_inner, font=('Consolas', 9), state=DISABLED,
                             wrap=NONE, bg='#f5f5f5')
        log_scroll_y = Scrollbar(log_inner, orient='vertical', command=self.log_text.yview)
        log_scroll_x = Scrollbar(log_inner, orient='horizontal', command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=log_scroll_y.set, xscrollcommand=log_scroll_x.set)

        log_scroll_y.pack(side='right', fill='y')
        log_scroll_x.pack(side='bottom', fill='x')
        self.log_text.pack(side='left', fill='both', expand=True)

        # 下载进度条
        progress_frame = Frame(self.master, padx=10, pady=2)
        progress_frame.pack(fill='x')
        self.progress_label = Label(progress_frame, text='', font=('宋体', 9), width=20, anchor='w')
        self.progress_label.pack(side='left')
        from tkinter.ttk import Progressbar
        self.progress_bar = Progressbar(progress_frame, mode='determinate', length=600)
        self.progress_bar.pack(side='left', fill='x', expand=True, padx=5)

        # 底部按钮区域
        btn_frame = Frame(self.master, padx=10, pady=5)
        btn_frame.pack(fill='x')

        self.run_btn = Button(btn_frame, text='开始生成', command=self._run,
                              font=('宋体', 12, 'bold'), width=20, bg='#4CAF50', fg='white')
        self.run_btn.pack(side='left', padx=5)

        self.open_ip_btn = Button(btn_frame, text='打开IP分析结果', command=self._open_ip_report,
                                  font=('宋体', 10), width=20, state=DISABLED)
        self.open_ip_btn.pack(side='left', padx=5)

        self.open_report_btn = Button(btn_frame, text='打开值守日报', command=self._open_daily_report,
                                      font=('宋体', 10), width=20, state=DISABLED)
        self.open_report_btn.pack(side='right', padx=5)

        # 结果路径
        self.ip_report_path = None
        self.daily_report_path = None

    def _log(self, msg):
        def do_log():
            self.log_text.config(state=NORMAL)
            timestamp = datetime.now().strftime('%H:%M:%S')
            self.log_text.insert(END, f'[{timestamp}] {msg}\n')
            self.log_text.see(END)
            self.log_text.config(state=DISABLED)
        self.master.after(0, do_log)

    def _set_progress(self, value, maximum=None):
        def do_progress():
            if maximum is None:
                self.progress_bar.config(mode='indeterminate')
                if value > 0:
                    self.progress_bar.step(1)
                else:
                    self.progress_bar.stop()
                    self.progress_bar.config(mode='determinate')
            elif maximum == 0:
                self.progress_bar.config(mode='determinate', maximum=100, value=0)
                self.progress_label.config(text='')
            else:
                self.progress_bar.config(mode='determinate', maximum=maximum, value=value)
                pct = int(value / maximum * 100) if maximum > 0 else 0
                mb_done = value / (1024 * 1024)
                mb_total = maximum / (1024 * 1024)
                self.progress_label.config(text=f'{mb_done:.1f}/{mb_total:.1f}MB ({pct}%)')
        self.master.after(0, do_progress)

    def _load_biz_ips(self):
        f = filedialog.askopenfilename(
            title='选择业务IP Excel文件',
            filetypes=[('Excel文件', '*.xlsx *.xls'), ('所有文件', '*.*')],
            initialdir=runtime_dir
        )
        if not f:
            return
        count = load_external_excluded_ips(f)
        if count > 0:
            self.excluded_ip_label_var.set(f'已导入 {count} 条业务IP')
            self._log(f'已导入业务IP: {count} 条 (来源: {os.path.basename(f)})')
        else:
            self.excluded_ip_label_var.set('导入失败')
            messagebox.showwarning('提示', '未能从文件中加载到有效的IP，请检查文件格式（需包含IP列）')
            self._log(f'业务IP导入失败: {f}')

    def _load_terminal_ips(self):
        """导入终端IP地址表（外部Excel文件）"""
        f = filedialog.askopenfilename(
            title='选择终端IP地址表 Excel文件',
            filetypes=[('Excel文件', '*.xlsx *.xls'), ('所有文件', '*.*')],
            initialdir=runtime_dir
        )
        if not f:
            return
        try:
            set_terminal_ip_table_path(f)
            table = load_terminal_ip_table()
            count = len(table)
            if count > 0:
                self.terminal_ip_label_var.set(f'已导入 {count} 条终端IP')
                self._log(f'已导入终端IP表: {count} 条 (来源: {os.path.basename(f)})')
            else:
                self.terminal_ip_label_var.set('导入失败')
                messagebox.showwarning('提示', '未能从文件中加载到有效的IP，请检查文件格式')
                self._log(f'终端IP表导入失败: {f}')
        except Exception as e:
            self.terminal_ip_label_var.set('导入失败')
            self._log(f'终端IP表导入异常: {e}')

    def _select_files(self):
        files = filedialog.askopenfilenames(
            title='选择安全告警Excel文件',
            filetypes=[('Excel文件', '*.xlsx *.xls'), ('所有文件', '*.*')],
            initialdir=runtime_dir
        )
        if files:
            for f in files:
                if f not in self.input_files:
                    self.input_files.append(f)
                    self.file_listbox.insert(END, os.path.basename(f))
            # 从第一个文件名中提取日期
            first_file = files[0]
            stem = os.path.splitext(os.path.basename(first_file))[0]
            m = re.search(r'(\d{8})', stem)
            if m:
                self.date_var.set(m.group(1))
            self._log(f'已选择 {len(files)} 个文件')

    def _auto_detect(self):
        try:
            files, date = pick_input_and_date('*.xlsx')
            self.input_files = [str(f) for f in files]
            self.date_var.set(date)
            self.file_listbox.delete(0, END)
            for f in self.input_files:
                self.file_listbox.insert(END, os.path.basename(f))
            self._log(f'自动识别到 {len(files)} 个文件 (日期: {date})')
        except FileNotFoundError as e:
            messagebox.showwarning('提示', str(e))
            self._log(f'警告: {e}')
        except Exception as e:
            import traceback
            error_msg = f'_auto_detect回调错误: {str(e)}\n{traceback.format_exc()}'
            print(error_msg)
            messagebox.showerror('错误', error_msg)

    def _clear_files(self):
        # 获取选中的索引（从后往前删除，避免索引偏移）
        selected_indices = sorted(self.file_listbox.curselection(), reverse=True)
        if selected_indices:
            # 删除选中的文件
            for idx in selected_indices:
                del self.input_files[idx]
                self.file_listbox.delete(idx)
            self._log(f'已移除 {len(selected_indices)} 个选中文件')
        else:
            # 没有选中，清空全部
            self.input_files = []
            self.file_listbox.delete(0, END)
            self._log('文件列表已清空')

    def _run(self):
        try:
            if not self.input_files:
                messagebox.showwarning('提示', '请先选择或自动识别输入文件')
                return

            self.run_btn.config(state=DISABLED)
            self.open_ip_btn.config(state=DISABLED)
            self.open_report_btn.config(state=DISABLED)

            def worker():
                try:
                    date = self.date_var.get()

                    # 获取用户输入的重点工作总结
                    work_summary = self.work_summary_text.get('1.0', END).strip()

                    # 获取用户输入的待跟进事项
                    follow_items = self.follow_items_text.get('1.0', END).strip()

                    # 获取用户输入的情报动态
                    intel_items = self.intel_items_text.get('1.0', END).strip()
                    # 如果输入内容等于示例文本，视为未填写
                    intel_default_example = EXAMPLE_INTEL_ITEMS
                    if intel_items == intel_default_example:
                        intel_items = None

                    self._log('=' * 50)
                    self._log('步骤1: IP归属分析')
                    self._log('=' * 50)

                    path_objects = [Path(f) for f in self.input_files]
                    self.ip_report_path = generate_ip_report(path_objects, date)
                    self._log(f'IP归属分析完成: {self.ip_report_path}')

                    self._log('')
                    self._log('=' * 50)
                    self._log('步骤2: 生成值守日报')
                    self._log('=' * 50)

                    self.daily_report_path = generate_daily_report(path_objects, date, work_summary, follow_items, intel_items)
                    self._log(f'值守日报生成完成: {self.daily_report_path}')

                    self._log('')
                    self._log('=' * 50)
                    self._log('全部完成！')
                    self._log('=' * 50)

                    self.master.after(0, self._on_complete)

                except Exception as e:
                    self._log(f'错误: {str(e)}')
                    import traceback
                    self._log(traceback.format_exc())
                    self.master.after(0, lambda: self.run_btn.config(state=NORMAL))

            threading.Thread(target=worker, daemon=True).start()
        except Exception as e:
            import traceback
            error_msg = f'_run回调错误: {str(e)}\n{traceback.format_exc()}'
            print(error_msg)
            messagebox.showerror('错误', error_msg)

    def _on_complete(self):
        self.run_btn.config(state=NORMAL)
        self.open_ip_btn.config(state=NORMAL)
        self.open_report_btn.config(state=NORMAL)
        messagebox.showinfo('完成', 'IP归属分析和值守日报已生成')

    def _open_ip_report(self):
        if self.ip_report_path and os.path.exists(self.ip_report_path):
            os.startfile(str(self.ip_report_path))
        else:
            messagebox.showwarning('提示', 'IP分析结果文件不存在')

    def _open_daily_report(self):
        if self.daily_report_path and os.path.exists(self.daily_report_path):
            os.startfile(str(self.daily_report_path))
        else:
            messagebox.showwarning('提示', '值守日报文件不存在')

    # ---------------- 更新相关方法 ----------------
    def _check_update_manual(self):
        """手动检查更新按钮回调（强制弹窗）"""
        try:
            threading.Thread(target=self._run_update_with_gui, args=(True,), daemon=True).start()
        except Exception as e:
            import traceback
            self._log(f'检查更新启动失败: {e}\n{traceback.format_exc()}')

    def _check_update_startup(self):
        """启动时自动检查更新（静默模式：有更新才弹窗）"""
        try:
            self._run_update_with_gui(force_dialog=False)
        except Exception as e:
            # 启动自动检查失败不打扰用户，仅记录日志
            import traceback
            self._log(f'[更新] 自动检查失败: {e}\n{traceback.format_exc()}')

    def _run_update_with_gui(self, force_dialog):
        """带GUI回调的更新流程（线程内运行）"""
        def ask_confirm(msg):
            # 对话框必须在主线程弹出，通过after + 事件同步
            result = [False]
            done = threading.Event()
            def do_ask():
                try:
                    result[0] = messagebox.askyesno("发现更新", msg)
                finally:
                    done.set()
            self.master.after(0, do_ask)
            done.wait()
            return result[0]

        # A：更新源可配置——优先读取 config.ini [update] 段，未配置则回退内置 GitHub 源
        cfg_vu, cfg_eu = load_update_config()
        updater = AutoUpdater(
            current_version=self.app_version,
            progress_cb=self._set_progress,
            log_cb=self._log,
            ask_confirm_cb=ask_confirm,
            version_urls=cfg_vu or None,
            exe_urls=cfg_eu or None,
        )
        updater.run_update_flow(force_dialog=force_dialog)

        # C：手动检查时显式反馈结果（含失败原因），避免用户以为"卡住/程序故障"
        if force_dialog:
            err = getattr(updater, 'last_check_error', None)
            status = getattr(updater, 'last_status', None)
            if err:
                title, kind = "检查更新", "warning"
                msg = (f"未能检查到新版本。\n原因：{err}\n\n"
                       "建议：检查网络连接，或在 config.ini 的 [update] 段配置可达的内网更新源。")
            elif status in ("下载失败", "安装失败"):
                title, kind = "更新失败", "error"
                msg = f"更新未完成（{status}）。请查看下方日志，或手动从发布渠道获取新版本。"
            elif status == "用户取消":
                return
            else:
                title, kind = "检查更新", "info"
                msg = "当前已是最新版本。"
            def _show():
                try:
                    (messagebox.showwarning if kind == "warning"
                     else messagebox.showerror if kind == "error"
                     else messagebox.showinfo)(title, msg)
                except Exception:
                    pass
            self.master.after(0, _show)


def gui_main(app_version='1.5.0'):
    """GUI模式入口"""
    root = Tk()
    app = DailyReportGUI(root, app_version=app_version)
    root.mainloop()
