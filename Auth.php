<?php
namespace application\plugin\auth
{
use application\helper\LogHelper;

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
		private $additionalPartSQL = '';
		private $debug = array();
		
		const EXCEPTION_NO_USER = "No user by that name";
		const EXCEPTION_PASSWORD_MISMATCH = "Password doesn't match";
		const EXCEPTION_LOCKED_USER = "User has been locked out";
		const ERROR_AUTH_FAIL = "User and password do not match";
		const ERROR_LOCKED_USER = "User has been locked out";
		
		public function getDebug()
		{
			return $this->debug;
		}
		
		public function getAdditionalPartSQL()
		{
		    return $this->additionalPartSQL;
		}
		
		public function setAdditionalPartSQL($additionalPartSQL)
		{
		    $this->additionalPartSQL = $additionalPartSQL;
		    return $this;
		}
		
		public function init()
		{
			
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
            LogHelper::setLogClass('application.plugin.Saml');
            LogHelper::debug("Auth::login()");
            if (isset($this->plugin->Session->samlUserdata) /* and has data dir config*/) {
                LogHelper::debug("AUTH has samlUserData");
                
                // $this->plugin->Session->userID = 4; // fix with employee id
                // return true;
            }
      
			// Get the model & table details
			$config = Nutshell::getInstance()->config->plugin->Auth;
			$modelName			= $config->model;
			$usernameColumns	= $config->usernameColumns;
			$passwordColumnName	= $config->passwordColumn;
			$saltColumnName		= $config->saltColumn;
			$model = $this->plugin->MvcQuery->getModel($modelName);
			
			// Get the user row from the table
			$result = null;
			foreach ($usernameColumns as $usernameColumnName) {
				$result = $model->read(array($usernameColumnName => $username), array(), $this->additionalPartSQL);
				
				if ($result) {
					break;
				}
			}
			
			$success = true;
			if(!$result) // No user by that name or email
			{
				$this->debug = array('message' => self::ERROR_AUTH_FAIL, 'exception_message' => self::EXCEPTION_NO_USER, 'username_column' => $usernameColumns, 'username' => $username, 'additional_sql' => $this->additionalPartSQL);
				$success = false;
			}
			else // There is a user by this name
			{
				// does that user's salted password match this salted password?
				$user					= $result[0];
				$salt					= $user[$saltColumnName];
				$realPasswordSalted		= $user[$passwordColumnName];
				$providedPasswordSalted	= $this->saltPassword($salt, $providedPassword);
				
				if($realPasswordSalted != $providedPasswordSalted)
				{
					$this->debug = array('message' => self::ERROR_AUTH_FAIL, 'exception_message' => self::EXCEPTION_PASSWORD_MISMATCH, 'real_salted' => $realPasswordSalted, 'provided_salted' => $providedPasswordSalted);
					$success = false;
				}
			
				// is failed login lockout enabled?
				if ($this->lockOutEnabled())
				{
					$success = $this->checkLockout($user, $success, $model);
				}
			}
			
			if ($success) {
				// Set the 'user' session variable
				$this->plugin->Session->userID = $user['id'];
			}
			
			return $success;
		}
		
		public function isLoggedIn()
		{
			return($this->getUserID() == true);
		}
		
		public function getUserID()
		{
			return $this->plugin->Session->userID;
		}
		
		public function logout()
		{
			$this->plugin->Session->userID = null;
			return true;
		}
		
		private function lockOutEnabled()
		{
			$config = Nutshell::getInstance()->config->plugin->Auth;
			$loginAttemptsColumn = $config->loginAttemptsColumn;
			$lockTimeColumn = $config->lockTimeColumn;
			$maxLoginAttempts = $config->maxLoginAttempts;
			$lockTimeoutPeriod = $config->lockTimeoutPeriod;
			
			return $maxLoginAttempts !== 0 && $lockTimeoutPeriod !== 0 && $loginAttemptsColumn !== "" && $lockTimeColumn !== "";
		}
		
		private function checkLockout($user, $success, $model)
		{
			$config = Nutshell::getInstance()->config->plugin->Auth;
			$loginAttemptsColumn = $config->loginAttemptsColumn;
			$lockTimeColumn = $config->lockTimeColumn;
			$maxLoginAttempts = $config->maxLoginAttempts;
			$lockTimeoutPeriod = $config->lockTimeoutPeriod;
			
			$now = time();
			// determine whetehr we are already locked out
			$loginAttempts = $user[$loginAttemptsColumn]; 
			$lockTime = $user[$lockTimeColumn];
			$lockedOut = false;
			if ($lockTime != 0) {
				$lockedOut = ($loginAttempts > $maxLoginAttempts) && ($now < ($lockTime + $lockTimeoutPeriod)); 
			}
			// establish what to do
			if ($success) {
				// login succeeded
				if ($lockedOut) {
					// but we are locked out
					$success = false;
					$this->debug = array('message' => self::ERROR_LOCKED_USER, 'exception_message' => self::EXCEPTION_LOCKED_USER, 'login_attempts' => $loginAttempts, 'lock_time' => $lockTime);
				} else {
					// if needed reset the login_attempt counter and lock time
					$lockTime = 0;
					$loginAttempts = 0;
				}
			} else {
				// login failed
				$loginAttempts++;
				if ($lockedOut) {
						// we are already locked out
						$this->debug = array('message' => self::ERROR_LOCKED_USER, 'exception_message' => self::EXCEPTION_LOCKED_USER, 'login_attempts' => $loginAttempts, 'lock_time' => $lockTime);
				} else {
					// we're not locked out, check if we should be
					if ($loginAttempts == $maxLoginAttempts) {
						$lockTime = $now;
						$this->debug = array('message' => self::ERROR_LOCKED_USER, 'exception_message' => self::EXCEPTION_LOCKED_USER, 'login_attempts' => $loginAttempts, 'lock_time' => $lockTime);
					}
				}
				
			}
			// update db to reflect attempts and lock time
			$model->update(array($loginAttemptsColumn => $loginAttempts, $lockTimeColumn => $lockTime), array('email' => $user['email']));
			
			return $success;
		}
	}
}
