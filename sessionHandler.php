<?php
define('SESSION_SAVE_PATH', dirname(realpath(__FILE__)). DIRECTORY_SEPARATOR. 'sessions');

/**
 * Class AppSessionHandler
 */
class AppSessionHandler extends SessionHandler
{
    private $sessionName = 'MYAPPSESS';
    private $sessionMaxLifetime = 0;
    private $sessionSSL = false;
    private $sessionHTTPOnly = true;
    private $sessionPath = '/';
    private $sessionDomain = '.classes.dev';
    private $sessionSavePath = SESSION_SAVE_PATH;
    private $sessionCipherAlog = MCRYPT_BLOWFISH;
    private $sessionCipherMode = MCRYPT_MODE_ECB;
    private $sessionCipherKey = 'WYCRYPT0K3Y@2017';
    private $ttl = 30;

    /**
     * AppSessionHandler constructor.
     */
    public function __construct()
    {
        // php.ini change settings
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_trans_sid', 0);
        ini_set('session.save_handler', 'files');

        // session name
        session_name($this->sessionName);

        // session path
        session_save_path($this->sessionSavePath);

        // set cookie parameters
        session_set_cookie_params(
            $this->sessionMaxLifetime,
            $this->sessionPath,
            $this->sessionDomain,
            $this->sessionSSL,
            $this->sessionHTTPOnly
        );
        // make this class in charge instead of default php session class
        session_set_save_handler($this, true);
    }

    public function __get($key)
    {
        return false !== $_SESSION[$key] ? $_SESSION[$key] : false;
    }

    public function __set($key, $value)
    {
       $_SESSION[$key] = $value;
    }

    public function __isset($key)
    {
        return isset($_SESSION[$key]) ? true : false;
    }

    public function read($session_id)
    {
        return mcrypt_decrypt($this->sessionCipherAlog, $this->sessionCipherKey, parent::read($session_id),$this->sessionCipherMode);
    }

    public function write($session_id, $session_data)
    {
       return parent::write($session_id, mcrypt_encrypt($this->sessionCipherAlog, $this->sessionCipherKey, $session_data,$this->sessionCipherMode));
    }

    /**
     * start new session
     */
    public function start(){
        if('' === session_id()){
            if(session_start()){
                $this->setSessionStartTime();
                $this->checkSessionValidity();
            }
        }
    }

    /**
     * set the session start time
     */
    private function setSessionStartTime(){
        if(!isset($this->sessionStartTime)){
            $this->sessionStartTime = time();
        }
        return true;
    }

    /**
     * @return bool
     *
     */
    private function checkSessionValidity(){
        if(time() - $this->sessionStartTime > ($this->ttl * 60)){
            $this->renewSession();
        }
        return true;
    }

    /**
     * @return bool
     * make the session start time is the current time
     * and generate new session (new id)
     */
    private function renewSession(){
        $this->sessionStartTime = time();
        // true => delete old session file and write new one
        return session_regenerate_id(true);
    }

}

$se = new AppSessionHandler();
$se->start();




