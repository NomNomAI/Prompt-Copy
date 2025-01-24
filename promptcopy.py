import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import time
import logging
import threading
import re
import subprocess
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')

class DirectoryHandler(FileSystemEventHandler):
    def __init__(self, app, refresh_delay=0.5):
        self.app = app
        self.last_refresh = 0
        self.refresh_delay = refresh_delay
        self.event_queue = Queue()
        self.processing = False
        
    def on_any_event(self, event):
        current_time = time.time()
        if current_time - self.last_refresh > self.refresh_delay:
            if not self.processing:
                self.processing = True
                threading.Thread(target=self._process_events).start()
            self.event_queue.put(event)
            self.last_refresh = current_time
            
    def _process_events(self):
        try:
            while not self.event_queue.empty():
                event = self.event_queue.get()
                self.app.root.after(100, self.app.incremental_refresh, event.src_path)
        finally:
            self.processing = False

class FilePromptApp:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_variables()
        self.setup_ui()
        
    def setup_window(self):
        self.root.title("File Prompt App")
        self.root.geometry("900x600")
        self.root.configure(bg="#f4f4f4")
        self.root.iconbitmap("")
        
    def setup_variables(self):
        self.observer = None
        self.refresh_delay = 0.5
        self.handler = DirectoryHandler(self, self.refresh_delay)
        self.current_folder = ""
        self.files = {}
        self.checked_items = set()
        self.folder_cache = {}
        self.filename_index = {}  # {lowercase_name: (full_path, parent_path)}
        self.setup_styles()
        
    def setup_styles(self):
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 10), padding=5)
        style.configure("TLabel", font=("Arial", 10), background="#f4f4f4")
        style.configure("Treeview", font=("Arial", 10), rowheight=25)
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

    def setup_ui(self):
        self.create_prompt_area()
        self.create_checkboxes()
        self.create_treeview()
        self.create_buttons()
        self.create_context_menu()
        
        self.tree.bind("<Button-1>", lambda e: 'break' if self.tree.identify_region(e.x, e.y) == 'heading' else self.handle_click(e))
        self.tree.bind("<Button-3>", self.show_context_menu)
        
        # Only pack widgets that aren't top-level windows
        for child in self.root.winfo_children():
            if not isinstance(child, tk.Menu):
                child.pack_configure(pady=5)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open in Explorer", command=self.open_in_explorer)

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
            
    def open_in_explorer(self):
        selected = self.tree.selection()
        if not selected:
            return
            
        item_id = selected[0]
        path = self.files.get(item_id)
        if path:
            subprocess.run(['explorer', '/select,', os.path.normpath(path)])
        else:
            text = self.tree.item(item_id)["text"].replace("☐ ", "").replace("☑ ", "")
            folder_path = os.path.join(self.current_folder, text)
            subprocess.run(['explorer', os.path.normpath(folder_path)])

    def create_prompt_area(self):
        frame = ttk.Frame(self.root)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.prompt_label = ttk.Label(frame, text="Prompt:")
        self.prompt_label.pack(anchor="w")
        
        self.prompt_text = tk.Text(frame, height=4, wrap="word", font=("Arial", 10))
        self.prompt_text.pack(fill=tk.BOTH, expand=True)

    def create_checkboxes(self):
        self.checkbox_frame = ttk.Frame(self.root)
        self.checkbox_frame.pack(pady=5, anchor="w", padx=10)
        
        self.add_script_fix_var = tk.BooleanVar()
        self.add_script_fix_checkbox = ttk.Checkbutton(
            self.checkbox_frame,
            text="Add 'send full script with fix' to prompt",
            variable=self.add_script_fix_var
        )
        self.add_script_fix_checkbox.pack(side=tk.LEFT, padx=(0, 10))
        
        self.not_react_var = tk.BooleanVar()
        self.not_react_checkbox = ttk.Checkbutton(
            self.checkbox_frame,
            text="Add 'This project is not React, fix code given' to prompt",
            variable=self.not_react_var
        )
        self.not_react_checkbox.pack(side=tk.LEFT)

    def create_treeview(self):
        self.tree_frame = ttk.Frame(self.root)
        self.tree_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        search_frame = ttk.Frame(self.tree_frame)
        search_frame.pack(fill=tk.X, pady=(0, 5))
        
        search_label = ttk.Label(search_frame, text="Search:")
        search_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_tree)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(fill=tk.X)
        self.search_entry.configure(state='disabled')
        
        self.tree = ttk.Treeview(self.tree_frame, selectmode="browse")
        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill="y")
        
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.tree.heading("#0", text="Folders and Files", anchor="w")

    def create_buttons(self):
        self.button_frame = ttk.Frame(self.root)
        self.button_frame.pack(pady=10)
        
        self.select_folder_button = ttk.Button(
            self.button_frame, 
            text="Select Folder", 
            command=self.select_folder
        )
        self.select_folder_button.grid(row=0, column=0, padx=5)
        
        self.copy_button = ttk.Button(
            self.button_frame, 
            text="Copy", 
            command=self.copy_to_clipboard
        )
        self.copy_button.grid(row=0, column=1, padx=5)

    def build_filename_index(self, folder_path):
        self.filename_index = {}
        for root, dirs, files in os.walk(folder_path):
            for name in files + dirs:
                self.filename_index[name.lower()] = (os.path.join(root, name), root)
                
    def filter_tree(self, *args):
        search_term = self.search_var.get().lower()
        if not search_term:
            self.refresh_tree()
            return
            
        self.tree.delete(*self.tree.get_children())
        
        matches = {
            path: parent 
            for name, (path, parent) in self.filename_index.items() 
            if search_term in name.lower()
        }
        
        if not matches:
            return
            
        # Get all parent paths that need to be shown
        all_paths = set()
        for path in matches:
            current = path
            while current != self.current_folder:
                all_paths.add(current)
                current = os.path.dirname(current)
        
        # Create nodes for all paths
        created_nodes = {}
        for path in sorted(all_paths):
            parent_path = os.path.dirname(path)
            parent_id = created_nodes.get(parent_path, "") if parent_path != self.current_folder else ""
            
            filename = os.path.basename(path)
            node_id = self.tree.insert(parent_id, "end", text=f"☐ {filename}" if os.path.isfile(path) else filename, open=True)
            created_nodes[path] = node_id
            
            if os.path.isfile(path):
                self.files[node_id] = path

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if not folder_path:
            return

        self.current_folder = folder_path
        self.folder_cache.clear()
        self.build_filename_index(folder_path)
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        self.observer = Observer()
        self.observer.schedule(self.handler, folder_path, recursive=True)
        self.observer.start()
        
        self.search_entry.configure(state='normal')
        self.refresh_tree()

    def refresh_tree(self):
        expanded_nodes = [item for item in self.tree.get_children() 
                         if self.tree.item(item)["open"]]
        checked_paths = {self.files[item_id]: item_id 
                        for item_id in self.checked_items}
        
        self.tree.delete(*self.tree.get_children())
        self.files.clear()
        self.checked_items.clear()
        
        if self.current_folder:
            root_id = self.populate_tree(self.current_folder, "")
            
            self.tree.item(root_id, open=True)
            for node in expanded_nodes:
                if node in self.tree.get_children():
                    self.tree.item(node, open=True)
            
            for new_id, path in self.files.items():
                if path in checked_paths:
                    self.toggle_checkbox(new_id)

    def incremental_refresh(self, changed_path):
        try:
            if os.path.exists(changed_path):
                if os.path.isfile(changed_path):
                    self.update_file(changed_path)
                else:
                    self.update_directory(changed_path)
            else:
                self.remove_path(changed_path)
                
            parent_path = os.path.dirname(changed_path)
            if parent_path in self.folder_cache:
                self.folder_cache[parent_path] = self._cache_folder_contents(parent_path)
            
            # Update filename index
            self.build_filename_index(self.current_folder)
                
        except Exception as e:
            logging.error(f"Error in incremental refresh: {e}")

    def _cache_folder_contents(self, folder_path):
        cache = {}
        try:
            entries = self.get_sorted_entries(folder_path)
            for entry in entries:
                item_id = self.find_node_by_name(self.find_node_by_path(folder_path), entry.name)
                if item_id:
                    cache[entry.name] = item_id
        except Exception as e:
            logging.error(f"Error caching folder contents: {e}")
        return cache

    def update_file(self, file_path):
        parent_path = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        
        parent_id = self.find_node_by_path(parent_path)
        if not parent_id:
            return
            
        existing_id = self.find_node_by_name(parent_id, file_name)
        if existing_id:
            self.tree.item(existing_id, text=f"☐ {file_name}")
        else:
            file_id = self.tree.insert(parent_id, "end", text=f"☐ {file_name}")
            self.files[file_id] = file_path

    def update_directory(self, dir_path):
        parent_path = os.path.dirname(dir_path)
        dir_name = os.path.basename(dir_path)
        
        parent_id = self.find_node_by_path(parent_path)
        if not parent_id:
            return
            
        existing_id = self.find_node_by_name(parent_id, dir_name)
        if not existing_id:
            self.populate_tree(dir_path, parent_id)

    def populate_tree(self, folder_path, parent):
        folder_name = os.path.basename(folder_path)
        folder_id = self.tree.insert(parent, "end", text=f"{folder_name}")

        try:
            entries = self.get_sorted_entries(folder_path)
            self.folder_cache[folder_path] = {}
            
            for entry in entries:
                if entry.is_dir():
                    dir_id = self.populate_tree(entry.path, folder_id)
                    self.folder_cache[folder_path][entry.name] = dir_id
                else:
                    file_id = self.tree.insert(folder_id, "end", text=f"☐ {entry.name}")
                    self.files[file_id] = entry.path
                    self.folder_cache[folder_path][entry.name] = file_id
                    
        except PermissionError as e:
            logging.error(f"Permission error accessing {folder_path}: {e}")
            
        return folder_id

    def get_sorted_entries(self, folder_path):
        try:
            entries = sorted(os.scandir(folder_path),
                           key=lambda e: (e.is_file(), e.name.lower()))
            return [e for e in entries 
                   if not (e.name.startswith("__") or
                          e.name.endswith(".db") or
                          e.name.lower() in ["venv", ".env", ".gitignore"])]
        except PermissionError as e:
            logging.error(f"Permission error accessing {folder_path}: {e}")
            return []
        except Exception as e:
            logging.error(f"Error accessing {folder_path}: {e}")
            return []

    def find_node_by_path(self, path):
        if not path or path == self.current_folder:
            return ""
            
        parts = os.path.relpath(path, self.current_folder).split(os.sep)
        current_id = ""
        
        for part in parts:
            found = False
            for child_id in self.tree.get_children(current_id):
                if self.tree.item(child_id)["text"].replace("☐ ", "").replace("☑ ", "") == part:
                    current_id = child_id
                    found = True
                    break
            if not found:
                return None
        return current_id

    def find_node_by_name(self, parent_id, name):
        for child_id in self.tree.get_children(parent_id):
            if self.tree.item(child_id)["text"].replace("☐ ", "").replace("☑ ", "") == name:
                return child_id
        return None

    def remove_path(self, path):
        node_id = self.find_node_by_path(path)
        if node_id:
            self.tree.delete(node_id)
            if node_id in self.files:
                del self.files[node_id]
            self.checked_items.discard(node_id)

    def handle_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return
            
        bbox = self.tree.bbox(item_id)
        if not bbox:
            return
            
        level = self.get_item_level(item_id)
        base_offset = 8
        indent_per_level = 20
        click_start = base_offset + (level * indent_per_level)
        click_end = click_start + 25
            
        click_x = event.x - bbox[0]
        if click_start <= click_x <= click_end:
            self.toggle_checkbox(item_id)

    def get_item_level(self, item_id):
        level = 0
        parent = self.tree.parent(item_id)
        while parent:
            level += 1
            parent = self.tree.parent(parent)
        return level

    def set_checkbox_state(self, item_id, checked):
        item_text = self.tree.item(item_id)["text"]
        new_text = item_text.replace("☐", "☑") if checked else item_text.replace("☑", "☐")
        self.tree.item(item_id, text=new_text)
        
        if checked:
            self.checked_items.add(item_id)
        else:
            self.checked_items.discard(item_id)
            
        for child_id in self.tree.get_children(item_id):
            self.set_checkbox_state(child_id, checked)

    def toggle_checkbox(self, item_id):
        item_text = self.tree.item(item_id)["text"]
        self.set_checkbox_state(item_id, "☐" in item_text)

    def copy_to_clipboard(self):
        selected_files = [self.files[item_id] for item_id in self.checked_items]
        if not selected_files:
            messagebox.showwarning("No Selection", "Please select at least one file.")
            return

        try:
            clipboard_content = self.build_clipboard_content(selected_files)
            self.root.clipboard_clear()
            self.root.clipboard_append(clipboard_content)
            self.root.update()
            messagebox.showinfo("Success", "Content copied to clipboard!")
        except Exception as e:
            logging.error(f"Error copying to clipboard: {e}")
            messagebox.showerror("Error", f"Failed to copy content: {str(e)}")

    def build_clipboard_content(self, selected_files):
        content = []
        prompt = self.prompt_text.get("1.0", tk.END).strip()
        
        if prompt:
            if self.add_script_fix_var.get():
                prompt += " send full script with fix"
            if self.not_react_var.get():
                prompt += " This project is not React, fix code given"
            content.append(f"Prompt: {prompt}\n")

        for file_path in selected_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
                    file_content = file.read()
                content.append(f"Filename: {os.path.basename(file_path)}\nContents:\n{file_content}\n")
            except FileNotFoundError:
                content.append(f"Error: File not found: {file_path}\n")
            except PermissionError:
                content.append(f"Error: Permission denied: {file_path}\n")
            except Exception as e:
                content.append(f"Error reading {file_path}: {str(e)}\n")
                
        return "\n".join(content)

    def cleanup(self):
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=2)
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FilePromptApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [app.cleanup(), root.destroy()])
    root.mainloop()