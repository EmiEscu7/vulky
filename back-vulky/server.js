import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { cryptPass, decrypt, hashPass } from './cryption.js';
import morgan from 'morgan';
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
app.use(cors({
    origin: '*', // O especifica la IP o dominio de tu app si es necesario
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type'],
}));
app.use(morgan('combined'));
app.disable('x-powered-by');

// Ruta para obtener usuarios
app.get('/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM USERS');
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error getting users.');
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
        res.status(201).send('User added');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error adding user.');
    }
});

app.get('/getPassesByUser', async (req, res) => {
    const userId = req.query.userId;
    try {
        const query = 'SELECT p.* FROM PASSES p JOIN USERS u ON p.id_user = u.id WHERE u.id = $1';
        console.log(query)
        const result = await pool.query(query, [userId]);
        res.header('Access-Control-Allow-Origin', '*');
        res.json(result.rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({'error': 'Error obtaining user passwords ' + userId});
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
        res.status(500).send('Error adding record.');
    }
});

app.get('/getInfoPass', async (req, res) => {
    const passId = req.query.passId;
    try {
        const query = 'SELECT p.* FROM PASSES p where id = $1'
        const result = await pool.query(query, [passId]);
        if(result.rowCount == 0) {
            res.status(500).send('No information found');
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
        res.status(500).send('Error obtaining password information for ' + passId);
    }
})

app.get('/crypt', (req, res) => {
    const pass = req.query.pass;
    const encrypted = cryptPass(pass);
    res.json({"encrypted": encrypted})
})

app.post('/login', async (req, res) => {
    const { user, pass } = req.body;
    console.log(`/login, user=${user}, pass=${pass}`)
    try {
        if(!user || !pass) {            
            res.status(500).json({'error': 'Wold be put username and password'});
        } else {
            const query = `SELECT u.* FROM USERS u WHERE username = '${user.trim()}'`;
            const result = await pool.query(query);
            if(result.rowCount == 0) {
                res.status(500).json({'error': 'No se encontró el usuario: ' + user});
            } else {
                const pass_hashed = hashPass(pass);
                const row = result.rows[0];
                if(row.password.toUpperCase() == pass_hashed.toUpperCase()) {
                    res.json({'userId': row.id});
                } else {
                    res.status(500).json({'error': 'Incorrect password.'});
                }
            }
            
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({'error': 'Error when login.'});
    }
});

app.post('/signin', async (req, res) => {
    const { user, password, birthdate, name, lastname } = req.body;
    console.log(`/signin, user=${user}, pass=***, birthdate=${birthdate}, name=${name}, lastname=${lastname}`);
    try {
        const user_id = uuidv4();
        const pass_hashed = hashPass(password.trim());
        await pool.query(
            'INSERT INTO USERS (id, name, lastname, birthdate, username, password, profile_pic) VALUES ($1, $2, $3, $4, $5, $6, null)',
            [user_id, name.trim(), lastname.trim(), birthdate.trim(), user.trim(), pass_hashed]
        );

        res.json({'message': 'User added.'});
    } catch (error) {
        console.error(error);
        // Verificar si el error es por clave única duplicada
        if (error.code === '23505') {
            res.status(400).json({ 'error': 'Username has already exist.' });
        } else {
            console.error(error);
            res.status(500).json({'error': 'Error when added user.'});
        }
        res.status(500).json({'error': 'Error when added user.'});
    }
});

app.post('/deleteAccount', async (req, res) => {
    const { username } = req.body;
    try {
        const userId = await pool.query('SELECT id FROM USERS WHERE username = $1', [username]);
        if(userId) {
            await pool.query('DELETE FROM PASSES WHERE user_id = $1', [userId]);
            await pool.query('DELETE FROM USERS WHERE ID = $1', [userId]);
            res.json({'message': 'user was deleted.'});
        } else {
            res.status(500).json({'error': 'No user was found with the identifier ' + username});
        }
    } catch (error) {
        res.status(500).json({'error': error});
    }
});

app.post('/deletePass', async (req, res) => {
    const { passId } = req.body;
    try {
        await pool.query('DELETE FROM PASSES WHERE id = $1', [passId]);
    } catch (error) {
        res.status(500).json({'error': error});
    }
});

app.get('/deleteAccount', async (req, res) => {
    const username = req.query.username;
    try {
        const userId = await pool.query('SELECT id FROM USERS WHERE username = $1', [username]);
        if(userId) {
            await pool.query('DELETE FROM PASSES WHERE id_user = $1', [userId]);
            await pool.query('DELETE FROM USERS WHERE ID = $1', [userId]);
            res.json({'message': 'user was deleted.'});
        } else {
            res.status(500).json({'error': 'No user was found with the identifier ' + username});
        }
    } catch (error) {
        res.status(500).json({'error': error});
    }
});

app.get('/deletePass', async (req, res) => {
    const passId = req.query.passId;
    try {
        await pool.query('DELETE FROM PASSES WHERE id = $1', [passId]);
    } catch (error) {
        res.status(500).json({'error': error});
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
