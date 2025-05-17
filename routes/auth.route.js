const { Router } = require('express');
//const { check } = require('express-validator');
const { login, crearUsuario } = require('../controllers/auth.controller');
//const { validarCampos } = require('../middlewares/validar-campos');

const router = Router();


router.post('/login',[
    //check('correo','El correo es obligatorio').isEmail(),
    //check('password','La contraseña es obligatoria').not().isEmpty(),
    //validarCampos
], login);

router.post('/register', [
  // Aquí puedes agregar middlewares de validación si quieres
], crearUsuario);

module.exports = router;