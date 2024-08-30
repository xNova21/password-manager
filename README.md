# Password Management Application

#### Video Demo: <https://youtu.be/qKH7XsCXe3Q>

## Overview

This project is a web application for managing saved passwords and ramdomly generate new ones. It allows users to securely store, view, and manage their passwords for various services. The application is built using Flask, a lightweight web framework for Python, and includes features such as user authentication, flash messages for notifications, and secure password storage.

## Features

- **User Authentication**: Secure login and logout functionality.
- **Password Management**: Add, view, edit, and delete saved passwords.
- **Flash Messages**: Informative messages for user actions.
- **Responsive Design**: User-friendly interface that works on various devices.

## Project Structure

### `app.py`

This is the main application file that initializes the Flask app, sets up routes, and handles the core logic of the application.

- **Routes**:
  - `/`: The home page that return the login page. Redirect to list if user is authenticated.
  - `/register`: The register page for user authentication.
  - `/logout`: The logout route to end the user session.
  - `/list`: The route to display the list of saved passwords. Also includes the functionality to delete passwords.
  - `/generate_new`: The route to generate a new random password.
  - `/add_new`: The route to add a new password.
  - `/edit/<id>`: The route to edit an existing password.

### `templates/`

This directory contains the HTML templates used by the Flask application.

- **`add.html`**: The template for adding a new password. It includes a form to enter the service name, username, and password.
- **`edit.html`**: The template for editing an existing password. It includes a form to update the service name, username, and password.
- **`generate_new.html`**: The template for generating a new random password. It includes a form to specify the length and complexity of the password.
- **`list.html`**: The template for displaying the list of saved passwords. It includes a logout button and a table of passwords.
- **`login.html`**: The template for the login page.
- **`register.html`**: The template for the register page.
- **`result.html`**: The template for displaying the result of random password generation.

### `static/`

This directory contains static files such as CSS and JavaScript.

- **`styles.css`**: The main stylesheet for the application.

### `README.md`

This file provides an overview of the project, its structure, and instructions for setting up and running the application.

## Design Choices

### User Authentication

I chose to implement user authentication to ensure that only authorized users can access and manage their passwords. This is achieved using Flask's session management and secure password hashing.
When a user registers, their password is hashed using the `bcrypt` library before being stored in the database, also generate a random key used to encrypt credentials info, that way, if DB is opened outside this app without correct login, all sensible data are hashed. When a user logs in, the hashed password is compared with the stored hash to authenticate the user and use the user key to decrypt the credentials info.

### Flash Messages

Flash messages are used to provide feedback to the user for various actions, such as successful login, logout, and password management operations. This enhances the user experience by keeping them informed about the status of their actions.

### Responsive Design

The application is designed to be responsive, ensuring that it works well on different devices, including desktops, tablets, and smartphones. This is achieved using CSS media queries and a flexible layout.

## Setup and Installation

### Prerequisites

- Python 3.x
- Flask
- SQLite
- bcrypt

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/me50/xNova21.git
   cd xNova21
   git checkout cs50/problems/2024/x/project
   ```

2. Create a virtual environment and activate it:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the application:

   ```bash
   flask run
   ```

5. Open your web browser and navigate to `http://127.0.0.1:5000/`.

## Usage

1. **Login**: Navigate to the login page and enter your credentials to log in.
2. **View Passwords**: After logging in, you will be redirected to the home page where you can view your saved passwords.
3. **Generate Password**: Click on the "Generate Password" button to generate a new random password.
4. **Add Password**: Click on the "Add Password" button to add a new password.
5. **Edit Password**: Click on the "Edit" button next to a password to edit it.
6. **Delete Password**: Click on the "Delete" button next to a password to delete it.
7. **Logout**: Click on the "Log Out" button to log out of the application.

## Conclusion

This project demonstrates a simple yet functional password management application using Python, Flask, SQLite, HTML, CSS and JS. It covers essential features such as user authentication, password management, and responsive design. The project structure is organized to separate concerns and make it easy to maintain and extend.
