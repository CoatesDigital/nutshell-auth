<?php
namespace application\plugin\auth
{
	use nutshell\Nutshell;
	use nutshell\behaviour\Singleton;
	use nutshell\core\plugin\Plugin;
	use application\plugin\auth\AuthException;
	use application\plugin\mvcQuery\MvcQuery;
	use application\plugin\appplugin\AppPlugin;
	
	/**
	 * @author Dean Rather
	 */
	class Auth extends AppPlugin implements Singleton
	{
		public function init()
		{
			require_once(__DIR__._DS_.'AuthException.php');
		}
		
		public function generateSalt()
		{
			mt_srand(microtime(true)*100000 + memory_get_usage(true));
			return md5(uniqid(mt_rand(), true));
		}
		
		public function saltPassword($salt, $password)
		{
			return sha1($salt.$password);
		}
		
		public function login($username, $providedPassword)
		{
			// Get the model & table details
			$config = Nutshell::getInstance()->config;
			$modelName			= $config->plugin->Auth->model;
			$usernameColumnName	= $config->plugin->Auth->usernameColumn;
			$passwordColumnName	= $config->plugin->Auth->passwordColumn;
			$saltColumnName		= $config->plugin->Auth->saltColumn;
			$model = $this->plugin->MvcQuery->getModel($modelName);
			
			// Get the user row from the table
			$whereKeyVals = array
			(
				$usernameColumnName => $username
			);
			$result = $model->read($whereKeyVals);
			
			// No user by that name
			if(!$result) return false;
			
			// does that user's salted password match this salted password?
			$user					= $result[0];
			$salt					= $user[$saltColumnName];
			$realPasswordSalted		= $user[$passwordColumnName];
			$providedPasswordSalted	= $this->saltPassword($salt, $providedPassword);
			
			if($realPasswordSalted != $providedPasswordSalted) return false;
			
			// Set the 'user' session variable
			$this->plugin->Session->user = $user;
			return true;
		}
		
		public function isLoggedIn()
		{
			return ($this->plugin->Session->user == true);
		}
		
		public function logout()
		{
			$this->plugin->Session->user = null;
			return true;
		}
	}
}
