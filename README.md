Setup: Set the user Model and column names in config.

save:
$salt = $this->plugin->Auth->generateSalt();
$password = $this->plugin->Auth->saltPassword($salt, $password);
// save the user's salt and password

login:
$success = $this->plugin->Auth->login($email, $password);

check:
$this->plugin->Auth->isLoggedIn();

logout:
$this->plugin->Auth->logOut();