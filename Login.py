import mysql.connector
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
import hashlib

background="#06283D"
framebg="#EDEDED"
framefg="#06283D"

root=Tk()
root.title("Netmap Login")
root.geometry("1250x700+210+100")
root.config(bg=background)
root.resizable(True,True)

#icon for the login page
image_icon = PhotoImage(file="C:/Users/kunal/OneDrive/Desktop/my/python/NETMAP/image/Logo.png")
root.iconphoto(False,image_icon)

#background
frame=Frame(root, bg="red")
frame.pack(fill=Y)

backgroundimage=PhotoImage(file="C:/Users/kunal/OneDrive/Desktop/my/python/NETMAP/image/LOGIN.png")
Label(frame, image=backgroundimage).pack()

#user entry
def user_enter(e):
    user.delete(0,'end')

def user_leave(e):
    name=user.get()
    if name == '':
        user.insert(0,'UserID')

user = Entry(width=18, fg="#fff", border=0, bg="#375174", font=('Arial bold', 24))
user.insert(0,'UserID')
user.bind("<FocusIn>", user_enter)
user.bind("<FocusOut>", user_leave)
user.place(x=500, y=315)

#password entry
def password_enter(e):
    code.delete(0,'end')

def password_leave(e):
    if code.get() == '':
        code.insert(0,'Password')

code = Entry(width=18, fg="#fff", border=0, bg="#375174", font=('Arial bold', 24))
code.insert(0,'Password')
code.bind("<FocusIn>", password_enter)
code.bind("<FocusOut>", password_leave)
code.place(x=500, y=410)

#hide and show button
button_mode = True

def hide():
    global button_mode

    if button_mode:
        eyeButton.config(image=closeeye, activebackground="white")
        code.config(show="*")
        button_mode=False
    else:
        eyeButton.config(image=openeye, activebackground="white")
        code.config(show="")
        button_mode=True


openeye=PhotoImage(file="C:/Users/kunal/OneDrive/Desktop/my/python/NETMAP/image/openeye.png", width=38, height=38)
closeeye=PhotoImage(file="C:/Users/kunal/OneDrive/Desktop/my/python/NETMAP/image/close eye.png", width= 38, height=38)
eyeButton=Button(image=openeye, bg= "#375174", bd=0, command=hide)
eyeButton.place(x=780, y=410)

label=Label(root,text="Don't have an account?", fg="#fff", bg="#00264d", font=('Microsoft YaHei UI Light', 9))
label.place(x=500, y=520)

def register():
    root.destroy()
    import registeration

registerButton=Button(root, width=10, text="add new user", border=0, bg="#00264d", cursor='hand2', fg="#57a1f8", command=register)
registerButton.place(x=650, y=520) 


def connect_to_db():
    db = mysql.connector.connect(
        host="localhost",
        user="lonewolf",
        password="Kunal7860rr$",
        database="userregistration"
    )
    return db

def validate_user(username, password):
    db = connect_to_db()
    cursor = db.cursor()
    query = f"SELECT password FROM login WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    db.close()
    if result:
        stored_password = result[0]
        if password == stored_password:
            return True
    return False

attempt_count = 0

def on_login_click():
    global attempt_count
    
    username = user.get()
    password = code.get()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if validate_user(username, hashed_password):
        messagebox.showinfo("Success", "Login successful!")
        if attempt_count == 0:
            root.destroy()
    else:
        attempt_count += 1
        if attempt_count < 3:
            messagebox.showerror("Error", "Invalid user ID or password")
        else:
            messagebox.showerror("Error", "Error. Too many attempts!!!")
            root.quit()  # Quit the application after 3 attempts

login_button = Button(text="Login", command=on_login_click, width=20, height=1, font=('Arial Bold', 12), bd=0)
login_button.place(x=530, y=600)


root.mainloop()
import NETMAP


