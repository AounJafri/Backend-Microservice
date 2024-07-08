CREATE TABLE Users (
	userId SERIAL PRIMARY KEY,
	username VARCHAR(255) NOT NULL,
	password VARCHAR(255) NOT NULL,
	email VARCHAR(255) NOT NULL UNIQUE,
	role VARCHAR(50) CHECK (role IN ('customer', 'support_agent', 'admin')) NOT NULL
);

CREATE TABLE Tickets (
    ticketId INTEGER PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    status VARCHAR(50) CHECK (status IN ('open', 'in_progress', 'closed')) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Ticket_Assignments (
    assignmentId SERIAL PRIMARY KEY,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES Tickets(ticketId) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES Users(userId) ON DELETE CASCADE
);

