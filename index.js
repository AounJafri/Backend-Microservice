import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import pg from "pg";
import nodemailer from "nodemailer";
import bcrypt from "bcrypt";
import swaggerUi from "swagger-ui-express";
import swaggerJsdoc from "swagger-jsdoc";

dotenv.config();

// Swagger setup
const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Ticket Management API",
      version: "1.0.0",
      description: "API documentation for the Ticket Management system",
    },
    servers: [
      {
        url: "http://localhost:3000", // Change this to the URL of your deployed API
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: ["./index.js"], // Path to the API docs
};

const specs = swaggerJsdoc(options);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function sendEmail(to, subject, text) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log("Error sending email:", error);
    } else {
      console.log("Email sent:", info.response);
    }
  });
}

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

db.connect();

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

/**
 * @swagger
 * /:
 *   get:
 *     summary: Welcome message
 *     responses:
 *       200:
 *         description: Returns a welcome message
 */
app.get("/", (req, res) => {
  res.json("Welcome to the Home page of this Ticket management system");
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *               email:
 *                 type: string
 *     responses:
 *       200:
 *         description: User registered successfully
 *       400:
 *         description: Bad request
 */
app.post("/register", async (req, res) => {
  const { username, password, role, email } = req.body;

  if (!username || !password || !role || !email) {
    return res.status(400).send("All fields are required");
  }

  try {
    var hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      "Insert into Users (username,password,email,role) Values ($1,$2,$3,$4) Returning *;",
      [username, hashedPassword, email, role]
    );

    const key = jwt.sign(result.rows[0], process.env.SECRET_KEY);
    res.json({ accessToken: key });
  } catch (error) {
    console.log(error);
    res.status(500).send("Error registering user");
  }
});



function authenticateToken(req, res, next) {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1];

  if (token == null) res.status(401).send("Token not provided");

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) {
      res.status(403).send("Incorrect Token");
    } else {
      req.user = user;
      next();
    }
  });
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send("You don't have permission to use this endpoint");
    }
    next();
  };
}

// Define Swagger documentation for the remaining endpoints...
/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   userId:
 *                     type: integer
 *                   username:
 *                     type: string
 *                   email:
 *                     type: string
 *                   role:
 *                     type: string
 */
app.get("/users", authenticateToken, authorizeRoles("support_agent", "admin"), async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM Users");
    res.json(result.rows);
  } catch (error) {
    console.log(error);
  }
});

/**
 * @swagger
 * /users/{id}:
 *   get:
 *     summary: Get a specific user by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A single user
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userId:
 *                   type: integer
 *                 username:
 *                   type: string
 *                 email:
 *                   type: string
 *                 role:
 *                   type: string
 */
app.get("/users/:id", authenticateToken, authorizeRoles("support_agent", "admin"), async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM Users WHERE userId=$1", [
      parseInt(req.params.id),
    ]);
    res.json(result.rows[0]);
  } catch (error) {
    console.log(error);
    res.status(404).send("User of this id does not exist");
  }
});

/**
 * @swagger
 * /users/{id}:
 *   delete:
 *     summary: Delete a specific user by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       403:
 *         description: Forbidden
 */
app.delete("/users/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  await db.query("DELETE FROM Users Where userId=$1", [
    parseInt(req.params.id),
  ]);
  res.json("Deleted successfully");
});

/**
 * @swagger
 * /users/deleteAll:
 *   delete:
 *     summary: Delete all users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: All users deleted successfully
 *       403:
 *         description: Forbidden
 */
app.delete("/users/deleteAll", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  await db.query("Truncate table Users");
  res.json("All Users deleted successfully");
});

/**
 * @swagger
 * /tickets:
 *   get:
 *     summary: Get all tickets
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all tickets
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   ticketId:
 *                     type: integer
 *                   title:
 *                     type: string
 *                   status:
 *                     type: string
 *                   created_at:
 *                     type: string
 *                     format: date-time
 */
app.get("/tickets", authenticateToken, authorizeRoles("support_agent", "admin"), async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM Tickets");
    res.json(result.rows);
  } catch (error) {
    console.log(error);
  }
});

/**
 * @swagger
 * /tickets/{id}:
 *   get:
 *     summary: Get a specific ticket by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the ticket
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A single ticket
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ticketId:
 *                   type: integer
 *                 title:
 *                   type: string
 *                 status:
 *                   type: string
 *                 created_at:
 *                   type: string
 *                   format: date-time
 */
app.get("/tickets/:id", authenticateToken, authorizeRoles("support_agent", "admin","customer"), async (req, res) => {
  try {
    const result = await db.query("SELECT * FROM Tickets WHERE ticketId=$1", [
      parseInt(req.params.id),
    ]);
    res.json(result.rows[0]);
  } catch (error) {
    console.log(error);
    res.status(404).send("Ticket of this id does not exist");
  }
});

/**
 * @swagger
 * /tickets:
 *   post:
 *     summary: Create a new ticket
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               id:
 *                 type: integer
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       201:
 *         description: Ticket created successfully
 *       400:
 *         description: Bad request
 */
app.post("/tickets", authenticateToken, authorizeRoles("customer", "admin"), async (req, res) => {
  const { title, id } = req.body;

  if (!title || !id) {
    return res.status(400).send("All fields are required");
  }

  try {
    const result = await db.query(
      "INSERT INTO Tickets (ticketId, title, status, created_at) VALUES ($1, $2,$3,$4) RETURNING *",
      [parseInt(id), title, "open",new Date()]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.log(error);
    res.status(500).send("Error creating ticket");
  }
});

/**
 * @swagger
 * /tickets/{id}:
 *   patch:
 *     summary: Update a specific ticket by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the ticket
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Ticket updated successfully
 *       400:
 *         description: Bad request
 */
app.patch("/tickets/:id", authenticateToken, authorizeRoles("support_agent", "admin","customer"), async (req, res) => {
  const { title } = req.body;
  const ticketId = parseInt(req.params.id);

  try {
    const result = await db.query(
      "UPDATE Tickets SET title=$1 WHERE ticketId=$2 RETURNING *",
      [title,ticketId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.log(error);
    res.status(500).send("Error updating ticket");
  }
});

/**
 * @swagger
 * /tickets/{id}:
 *   delete:
 *     summary: Delete a specific ticket by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the ticket
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Ticket deleted successfully
 *       403:
 *         description: Forbidden
 */
app.delete("/tickets/:id", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  await db.query("DELETE FROM Tickets WHERE ticketId=$1", [
    parseInt(req.params.id),
  ]);
  res.json("Deleted successfully");
});

/**
 * @swagger
 * /tickets/deleteAll:
 *   delete:
 *     summary: Delete all tickets
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: All tickets deleted successfully
 *       403:
 *         description: Forbidden
 */
app.delete("/tickets/deleteAll", authenticateToken, authorizeRoles("admin"), async (req, res) => {
  try {
    await db.query("TRUNCATE TABLE Tickets");
    res.json("All tickets deleted successfully");
    
  } catch (error) {
    
  }
});

/**
 * @swagger
 * /tickets/assign:
 *   post:
 *     summary: Assign a ticket to a particular user
 *     security:
 *       - bearerAuth: []
 *     tags: [Tickets]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: integer
 *                 description: ID of the user
 *               ticketId:
 *                 type: integer
 *                 description: ID of the ticket
 *     responses:
 *       200:
 *         description: Assignment Successful
 *       400:
 *         description: Bad request
 *       500:
 *         description: Server error
 */
app.post(
  "/tickets/assign",
  authenticateToken,
  authorizeRoles("support_agent", "admin"),
  async (req, res) => {
    const userId = parseInt(req.body.userId);
    const ticketId = parseInt(req.body.ticketId);
    try {
      await db.query(
        "Insert into Ticket_Assignments (ticket_id,user_id,assigned_at) Values($1,$2,$3)",
        [ticketId, userId, new Date()]
      );

      const result = await db.query("Select email from Users WHERE userId=$1", [
        userId,
      ]);

      const email = result.rows[0].email;
      sendEmail(email, 'Ticket Assigned', `Ticket ID ${ticketId} has been assigned to you.`);
      res.json("Assignment Successful");
    } catch (error) {
      console.log(error);
      res.status(500).send("Server error");
    }
  }
);


/**
 * @swagger
 * /assignedTickets:
 *   get:
 *     summary: Get all assigned tickets
 *     security:
 *       - bearerAuth: []
 *     tags: [Tickets]
 *     responses:
 *       200:
 *         description: List of assigned tickets
 *       500:
 *         description: Server error
 */
app.get(
  "/assignedTickets",
  authenticateToken,
  authorizeRoles("admin", "customer", "support_agent"),
  async (req, res) => {
    try {
      const result = await db.query(
        `SELECT t.ticketId, t.title, t.status, a.assigned_at, u.username as AssignedTo, u.userId 
         FROM Tickets t 
         JOIN Ticket_Assignments a ON t.ticketId = a.ticket_id 
         JOIN Users u ON u.userId = a.user_id;`
      );
      res.json(result.rows);
    } catch (error) {
      console.log(error);
      res.status(500).send("Server error");
    }
  }
);


/**
 * @swagger
 * /tickets/status/{id}:
 *   patch:
 *     summary: Update status of a ticket
 *     security:
 *       - bearerAuth: []
 *     tags: [Tickets]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the ticket
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *                 description: New status of the ticket
 *     responses:
 *       200:
 *         description: Ticket status updated successfully
 *       400:
 *         description: Bad request
 *       500:
 *         description: Server error
 */
app.patch(
  "/tickets/status/:id",
  authenticateToken,
  authorizeRoles("admin"),
  async (req, res) => {
    const ticketId = req.params.id;
    const newStatus = req.body.status;

    try {
      const result = await db.query(
        "Update Tickets SET status= $1 WHERE ticketId = $2 Returning *",
        [newStatus, parseInt(ticketId)]
      );
      res.json(result.rows[0]);
    } catch (error) {
      console.log(error);
      res.status(500).send("Server error");
    }
  }
);
app.listen(port, () => {
  console.log(`App is running at http://localhost:${port}`);
});
