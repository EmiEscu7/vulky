import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { cryptPass, decrypt, hashPass } from './cryption.js';
import dotenv from 'dotenv';
dotenv.config();

const DB_HOST = process.env.DB_HOST;
const DB_PORT = process.env.DB_PORT;
const DB_NAME = process.env.DB_NAME;
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;

const { Pool } = pkg;

const app = express();
const pool = new Pool({
    user: DB_USER,
    host: DB_HOST,
    database: DB_NAME,
    password: DB_PASS,
    port: DB_PORT,
    ssl: {
        rejectUnauthorized: false, // Para permitir conexiones SSL
    }
});

app.use(express.json());
app.use(cors());
app.disable('x-powered-by');

// Ruta para obtener usuarios
app.get('/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM USERS');
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al obtener usuarios');
    }
});

// Ruta para agregar un usuario
app.post('/users', async (req, res) => {
    const { name, lastname, birthdate, username, password } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO USERS (name, lastname, birthdate, username, password) VALUES ($1, $2, $3, $4, $5)',
            [name, lastname, birthdate, username, password]
        );
        res.status(201).send('Usuario agregado');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al agregar usuario');
    }
});

app.get('/getPassesByUser', async (req, res) => {
    const userId = req.query.userId;
    try {
        const query = 'SELECT p.* FROM PASSES p JOIN USERS u ON p.id_user = u.id';
        console.log(query)
        const result = await pool.query(query);
        res.header('Access-Control-Allow-Origin', '*');
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al obtener las contraseñas del usuario ' + userId);
    }
});

app.post('/addNewPass', async (req, res) => {
    const { app, user_app, pass_app, user_id } = req.body;
    console.log(app, user_app, pass_app, user_id);
    try {
        const pass = cryptPass(pass_app);
        const pass_id = uuidv4();
        await pool.query(
            'INSERT INTO PASSES (id, id_user, app, user_app, pass_app) VALUES ($1, $2, $3, $4, $5)',
            [pass_id, user_id, app, user_app, pass]
        );

        const last_pass = await pool.query('SELECT * FROM PASSES WHERE id = $1', [pass_id])
        res.status(201).json(last_pass.rows[0]);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al agregar el registro');
    }
});

app.get('/getInfoPass', async (req, res) => {
    const passId = req.query.passId;
    try {
        const query = 'SELECT p.* FROM PASSES p where id = $1'
        const result = await pool.query(query, [passId]);
        if(result.rowCount == 0) {
            res.status(500).send('No se encontró información');
        } else {
            const row = result.rows[0];
            console.log(row.pass_app);
            
            const passDecrypt = decrypt(row.pass_app);
            row['pass_app'] = passDecrypt;
            console.log(row);
            
            res.json(row);
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al obtener la informacion de la contraseña para ' + passId);
    }
})

app.get('/crypt', (req, res) => {
    const pass = req.query.pass;
    const encrypted = cryptPass(pass);
    res.json({"encrypted": encrypted})
})

app.post('/login', async (req, res) => {
    const { user, pass } = req.body;
    try {
        if(!user || !pass) {
            res.status(500).send('Debe ingresar usuario y contrasenia');
        } else {
            const query = `SELECT u.* FROM USERS u WHERE username = '${user.trim()}'`;
            console.log(query);            
            const result = await pool.query(query);
            if(result.rowCount == 0) {
                res.status(500).send('No se encontró el usuario: ' + user);
            } else {
                const pass_hashed = hashPass(pass);
                const row = result.rows[0];

                if(row.password.toUpperCase() == pass_hashed.toUpperCase()) {
                    res.json({'userId': row.id});
                } else {
                    res.status(500).send('La contrasenia es incorrecta');
                }
            }
            
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al iniciar sesion');
    }
});

app.post('/signin', async (req, res) => {
    const { user, password, birthdate, name, lastname } = req.body;
    console.log(user, password, birthdate, name, lastname);
    try {
        const user_id = uuidv4();
        await pool.query(
            'INSERT INTO USERS (id, name, lastname, birthdate, username, password, profile_pic) VALUES ($1, $2, $3, $4, $5, $6, null)',
            [user_id, name, lastname, birthdate, user, password]
        );

        res.status(201).send('User addeded.');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al agregar el registro');
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
