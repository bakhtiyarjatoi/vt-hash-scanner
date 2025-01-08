import tkinter as tk
from gui import HashReputationTool  

def main():
    """Initialize and run the Hash Reputation Tool."""
    root = tk.Tk()  
    app = HashReputationTool(root)  
    root.mainloop()  

if __name__ == "__main__":
    main()  
