const express = require('express')
const cors = require('cors')

const { bdmysql } = require('../database/MySqlConnection');

const { dbConnectionMongo } = require('../database/MongoConnection');


class Server {

    constructor() {
        this.app = express();
        this.port = process.env.PORT;

        
        this.pathsMySql = {
            //auth: '/api/auth',
            //heroes: '/api/heroes',
            //peliculas: '/api/peliculas',
        }
            
        this.pathsMongo = {

            //Ajusto la url para la outorizacion por login
            auth: '/api/auth',
            usuarios: '/api/usuarios',
            heroes:'/api/heroes',            
            multimedias:'/api/multimedias',
            multimediasheroe:'/api/multimediasheroe',
            grupomultimedias:'/api/grupomultimedias',

        }


        /*
        this.app.get('/', function (req, res) {
            res.send('Hola Mundo a todos... como estan...')
        })
        */    
        

        //Aqui me conecto a la BD
        //this.dbConnection();

        //Aqui me conecto a MongoDB
        this.conectarBDMongo();


        //Middlewares
        this.middlewares();


        //Routes
        this.routes();

    }


    
    async dbConnection() {
        try {
            await bdmysql.authenticate();
            console.log('Connection OK a MySQL.');
        } catch (error) {
            console.error('No se pudo Conectar a la BD MySQL', error);
        }
    }
    
    async conectarBDMongo(){
        await dbConnectionMongo();
    }

    
    routes() {


        /*
        this.app.get('/api', (req, res) => {
            //res.send('Hello World')
            res.json({ok:true,
                msg:'get API'
               })

        });

        this.app.post('/api', (req, res) => {
            //res.send('Hello World')
            res.status(201).json({ok:true,
                msg:'post API'
               })

        });

        this.app.put('/api', (req, res) => {
            //res.send('Hello World')
            res.json({ok:true,
                msg:'put API'
               })

        });

        this.app.delete('/api', (req, res) => {
            //res.send('Hello World')
            res.json({ok:true,
                msg:'delete API'
               })

        });

        this.app.patch('/api', (req, res) => {
            //res.send('Hello World')
            res.json({
                ok:true,
                msg:'patch API',
                status:'Status OK...'
               })

        });
        */
                   
        //this.app.use(this.pathsMySql.auth, require('../routes/MySqlAuth'));
        //this.app.use(this.pathsMySql.heroes, require('../routes/heroes.route'));
        
        this.app.use(this.pathsMongo.heroes, require('../routes/heroes'));
        this.app.use(this.pathsMongo.usuarios, require('../routes/mongoUsuario.route'));
        this.app.use(this.pathsMongo.grupomultimedias, require('../routes/grupomultimedias'));
        this.app.use(this.pathsMongo.multimedias, require('../routes/multimedias'));
        this.app.use(this.pathsMongo.multimediasheroe, require('../routes/multimediasHeroe'));

        //Activo la ruta del login
        this.app.use(this.pathsMongo.auth, require('../routes/auth.route'));
        
    }
    

    
    middlewares() {
        this.app.use(cors({
            origin: ['http://localhost:8100', 'https://base-movil-production.up.railway.app'],
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'x-token']
        }));

        // RESPUESTA A PRE-FLIGHT OPTIONS
        this.app.options('*', cors());

        this.app.use(express.json());
        this.app.use(express.static('public'));
    }

    

    listen() {
        this.app.listen(this.port, () => {
            console.log('Servidor corriendo en puerto', this.port);
        });
    }


}


module.exports = Server;
