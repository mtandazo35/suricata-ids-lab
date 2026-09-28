// El modal que sustituye a confirm() y alert() del navegador.
//
// Lo delicado no es el aspecto: es que una confirmacion tiene que dejar salir el envio
// ORIGINAL. Cada boton de estos lleva su name/value y a veces su propio formaction (la
// baja de un nodo, por ejemplo, va a /routers/quitar y no a la accion del form). Mandar
// el formulario a mano desde el modal perderia las dos cosas y la accion acabaria en la
// ruta equivocada, que en esta pagina significa cortarle el internet a quien no era.
//
// Por eso ask() devuelve false y, al confirmar, REPITE la misma pulsacion. Lo que se
// comprueba aqui es justo eso: que la primera vez no sale nada, que la segunda sale, que
// la marca no se queda pegada (si no, el siguiente clic no preguntaria) y que un <form>
// se manda con submit(), que no vuelve a disparar su propio onsubmit.
const fs = require('fs');
const js = fs.readFileSync(process.argv[2], 'utf8');

// --- DOM minimo ---
function el(id, extra) {
  return Object.assign({
    id, style: {}, textContent: '', className: '', dataset: {}, lis: {},
    focus() { this.enfoque = (this.enfoque || 0) + 1; },
    addEventListener(t, f) { this.lis[t] = f; },
    click() { return this.lis.click && this.lis.click(); }
  }, extra || {});
}

const askov = el('askov'), asktit = el('asktit'), asktxt = el('asktxt'),
      askok = el('askok'), askno = el('askno');
const els = { askov, asktit, asktxt, askok, askno };
const docLis = {};
global.document = {
  getElementById: id => (els[id] !== undefined ? els[id] : null),
  addEventListener(t, f) { docLis[t] = f; }
};
eval(js);

let fallos = 0;
const check = (d, c, e) => {
  console.log((c ? '  OK   ' : ' FALLA ') + d + (c ? '' : '  -> ' + JSON.stringify(e)));
  if (!c) fallos++;
};

// Un boton como los de Cuarentena: al pulsarlo el navegador corre su onclick, y solo
// manda el formulario si ese onclick devuelve true.
let enviados = 0;
const boton = el(null, { tagName: 'BUTTON', name: 'ip', value: '192.0.2.10' });
boton.lis.click = function () {
  const r = ask(boton, 'Enviar al MikroTik',
                '192.0.2.10 entra en la lista Cliente Virus.', 'Enviar');
  if (r) enviados++;
  return r;
};

// --- la primera pulsacion solo pregunta ---
boton.click();
check('la primera pulsacion no manda nada', enviados === 0, enviados);
check('y abre el modal', askov.style.display === 'flex', askov.style.display);
check('con el titulo de la accion', asktit.textContent === 'Enviar al MikroTik', asktit.textContent);
check('y diciendo que pasa despues, no solo preguntando',
      asktxt.textContent.indexOf('entra en la lista') > 0, asktxt.textContent);
check('el boton de aceptar lleva el verbo de la accion',
      askok.textContent === 'Enviar', askok.textContent);
check('se ofrece cancelar', askno.style.display === '', askno.style.display);
check('el foco arranca en el boton de aceptar', askok.enfoque === 1, askok.enfoque);
check('una accion que no corta a nadie no se pinta de peligro',
      askok.className === 'askok', askok.className);

// --- cancelar no ejecuta ---
askNo();
check('cancelar cierra el modal', askov.style.display === 'none', askov.style.display);
check('y no manda nada', enviados === 0, enviados);

// --- confirmar repite la MISMA pulsacion ---
boton.click();
askok.lis.click();
check('confirmar deja salir el envio original', enviados === 1, enviados);
check('y cierra el modal', askov.style.display === 'none', askov.style.display);
check('la marca interna no se queda pegada al boton', !boton.dataset.ok, boton.dataset.ok);

// Si la marca quedara puesta, el siguiente clic pasaria de largo sin preguntar: seria una
// accion que corta a un abonado sin confirmacion.
boton.click();
check('la siguiente vez vuelve a preguntar',
      enviados === 1 && askov.style.display === 'flex', [enviados, askov.style.display]);
askNo();

// --- tono de peligro ---
const bd = el(null, { tagName: 'BUTTON' });
bd.lis.click = () => ask(bd, 'Sacar de la lista', 'Vuelve a tener salida.', 'Quitar', 'danger');
bd.click();
check('lo que corta o suelta a alguien se pinta en rojo',
      askok.className === 'askok danger', askok.className);
askNo();
check('y el tono no se arrastra a la siguiente pregunta',
      (boton.click(), askok.className === 'askok'), askok.className);
askNo();

// --- un <form> con onsubmit (la baja de un usuario) ---
let submits = 0;
const form = el(null, { tagName: 'FORM', submit() { submits++; } });
const r1 = ask(form, 'Eliminar usuario', 'Dejara de poder entrar.', 'Eliminar', 'danger');
check('un form tampoco se manda a la primera', r1 === false && submits === 0, [r1, submits]);
askok.lis.click();
// submit() NO dispara onsubmit: por eso no hace falta marca y no hay bucle infinito
check('al confirmar se manda una sola vez', submits === 1, submits);

// --- aviso: lo que antes era alert() ---
aviso('Falta el archivo', 'Elige primero el archivo JSON que quieres importar.');
check('un aviso no ofrece cancelar', askno.style.display === 'none', askno.style.display);
check('su boton es de salida unica', askok.textContent === 'Entendido', askok.textContent);
check('un aviso no hereda el rojo de la pregunta anterior',
      askok.className === 'askok', askok.className);
askok.lis.click();
check('aceptar un aviso no ejecuta ninguna accion pendiente',
      enviados === 1 && submits === 1, [enviados, submits]);
check('y lo cierra', askov.style.display === 'none', askov.style.display);

// --- Escape ---
const b2 = el(null, { tagName: 'BUTTON' });
let ejec2 = 0;
b2.lis.click = () => { if (ask(b2, 'Quitar el nodo', 'x', 'Quitar', 'danger')) ejec2++; };
b2.click();
docLis.keydown({ key: 'Escape' });
check('Escape cierra', askov.style.display === 'none', askov.style.display);
check('y no ejecuta', ejec2 === 0, ejec2);
b2.click();
docLis.keydown({ key: 'Enter' });
check('otra tecla no cierra nada', askov.style.display === 'flex', askov.style.display);
askNo();

console.log('\n' + (fallos ? fallos + ' fallo(s)' : 'TODO OK'));
process.exit(fallos ? 1 : 0);
