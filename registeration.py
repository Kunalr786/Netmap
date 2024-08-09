import mysql.connector
from tkinter import *
from tkinter import messagebox
import hashlib

background="#06283D"
framebg="#EDEDED"
framefg="#06283D"

root=Tk()
root.title("Netmap User Registration")
root.geometry("1250x700+210+100")
root.config(bg=background)
root.resizable(True,True)

def register():
    username = user.get()
    password = code.get()
    admincode = adminaccess.get()

    if admincode == "ENTER ADMIN CODE":
        if (username == "" or username == "UserID") or (password == "" or password == "Password"):
            messagebox.showerror("Error", "All fields are required")
        else:
            try:
                mydb = mysql.connector.connect(
                    host="localhost",
                    user="ENTER USERNAME",
                    password="ENTER PASSWORD"
                )

                mycursor = mydb.cursor()

                # Check if the database exists
                mycursor.execute("SHOW DATABASES LIKE ''ENTER DATABASE NAME")
                result = mycursor.fetchone()

                if result is None:
                    # Database does not exist, create it
                    mycursor.execute("CREATE DATABASE #YOUR_DATABASE")
                    mycursor.execute("USE UserRegistration")

                    # Create the table
                    mycursor.execute("CREATE TABLE TABLE_NAME (id INT AUTO_INCREMENT,username VARCHAR(50) NOT NULL,password VARCHAR(500) NOT NULL,PRIMARY KEY (id))")
                else:
                    # Database exists, use it
                    mycursor.execute("USE #DATABASE")
                
                # Hash the password
                hashed_password = hashlib.sha256(password.encode()).hexdigest()

                # Insert the new user into the existing table
                query = "INSERT INTO TABLE_NAME(Username,Password) values(%s,%s)"
                mycursor.execute(query, (username, hashed_password))
                mydb.commit()

                messagebox.showinfo("Success", "User registered successfully")
                mydb.close()

            except mysql.connector.Error as err:
                messagebox.showerror("Error", "Connection to database failed: {}".format(err))

    else:
        messagebox.showerror("Error", "Invalid Admin Code")


def login():
    root.destroy()
    import Login

#icon for the login page
image_icon=PhotoImage(file="ENTER FILE PATH")
root.iconphoto(False,image_icon)

#background
frame=Frame(root, bg="red")
frame.pack(fill=Y)

backgroundimage=PhotoImage(file="ENTER FILE PATH")
Label(frame, image=backgroundimage).pack()

adminaccess= Entry(frame, width=15, fg="#000", border=0, bg="#e8ecf7", font=("Arial Bold", 20), show="*")
adminaccess.focus()
adminaccess.place(x=550, y=280)

#user entry
def user_enter(e):
    user.delete(0,'end')

def user_leave(e):
    name=user.get()
    if name == '':
        user.insert(0,'UserID')

user = Entry(width=18, fg="#fff",  border=0, bg="#375174", font=('Arial Bold', 20))
user.insert(0,'UserID')
user.bind("<FocusIn>", user_enter)
user.bind("<FocusOut>", user_leave)
user.place(x=500, y=380)

#password entry
def password_enter(e):
    code.delete(0,'end')

def password_leave(e):
    if code.get() == '':
        code.insert(0,'Password')

code = Entry(width=18, fg="#fff", border=0, bg="#375174", font=('Arial Bold', 24))
code.insert(0,'Password')
code.bind("<FocusIn>", password_enter)
code.bind("<FocusOut>", password_leave)
code.place(x=500, y=470)

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


openeye=PhotoImage(file="ENTER FILE PATH", width=38, height=38)
closeeye=PhotoImage(file="ENTER FILE PATH", width= 38, height=38)
eyeButton=Button(image=openeye, bg= "#375174", bd=0, command=hide)
eyeButton.place(x=780, y=470)

reg_button= Button(root, text="Add new user", bg="#455c88", fg="white", width=13, height=1, font= ("Arial",16,"bold"), bd=0, command=register)
reg_button.place(x=530, y=600)

back=PhotoImage(file="ENTER FILE PATH")
backButton=Button(root, image=back, fg="#deeefb", command=login)
backButton.place(x=20, y=15)

root.mainloop()
