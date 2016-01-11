"use strict";

import routes_ecdsa from "./ecdsa/routes_ecdsa"
import routes_rsa from "./rsa/routes_rsa"

const routes_api = {
  ecdsa: routes_ecdsa,
  rsa: routes_rsa
};

export default routes_api;