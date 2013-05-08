<?php
/**
 * honeypotject.php security pluging using Project Honeypot's Blocklists
 *
 * @package Plugin Project Honeypot Blocklists
 * @version $Id: honeypotject.php 001 2012-10-26 18:30:00Z eric $
 * @author Eric Bouquerel
 * @copyright (C) 2012 - Bol d'Air
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 **/

// no direct access
defined('_JEXEC') or die('Restricted access');

/**
 * class plgSystemHoneypotject
*/
class plgSystemHoneypotject extends JPlugin {
	/**
	 * Load the language file on instantiation.
	 *
	 * @var    boolean
	 * @since  3.1
	 */
	protected $autoloadLanguage= true;

	/**
	 * @protected
	 * @param object $subject The object to observe
	 * @config array $config An array that holds the plugin configuration
	 * @since 1.0
	 */
	public function __construct(&$subject, $config) {
		parent::__construct($subject, $config);
		$this->honeypotject_logme();
	}

	/**
	 * @fn onAfterInitialise
	 *
	 * Executes right after Joomla Initialisation, before anything else
	 	* To be certain we should urge the user to load that plugin as the 1st one
	 * Loads user defined plugin parameters
	 *
	 * @since 1.0
	 */
	function onAfterInitialise() {
		/**
		 * @var string plg_name the plugin'name
		 */
		$plg_name= "honeypotject";
		/**
		 * @var object mainframe contains Joomla Application
		 */
		$mainframe= &JFactory::getApplication();
		/**
		 * @var object session User's session
		*/
		$session= &JFactory::getSession();
		// Assign paths
		$sitePath= JPATH_SITE;
		$siteUrl= substr(JURI::root(), 0, -1);
		// Check if plugin is enabled
		if(JPluginHelper::isEnabled('system', $plg_name)) {
			/**
			 * @var object plugin the plugin itself
			 */
			$plugin= &JPluginHelper::getPlugin('system', $plg_name);
			/**
			 * @var string apikey contains the user's Project Honeypot API Key
			*/
			$apikey= $this->params->get('honeyproject_apikey');
			//either log an already checked IP, or check an ip
			if(isset($_COOKIE['notabot']) && $session->has('honeypotject')) {
				$this->honeypotject_logme();
				if($_SESSION['honeypotject']['activity'] < 8)
					$this->honeypotject_infected(); // Only display infection banner if last spam was less than 8 days ago.
			}
			else
				$this->honeypotject_check($apikey);
		}
	}

	/**
	 * @fn honeypotject_check
	 *
	 * Main Function checks the user's IP against the BlockList
	 * Performs a gethostByName on the remote user's IP address using Project Honeypot DNS and specially formatted DNS Queries
	 * If a result is found and identified as a threat, calls the logging, then the blocking functions
	 *
	 * @see honeypotject_logme function logs an indentified threat
	 * @see honeypotject_blockme function brings up a warning message, sends a 403 header and a javascript link for false positiive
	 * @param string $apikey A string containing the user's Projec Hopot's API Key
	 * @since 1.0
	 */
	function honeypotject_check($apikey) {
		$ip= $_SERVER['REMOTE_ADDR'];
		// build the lookup DNS query
		// Example : for '127.9.1.2' you should query 'abcdefghijkl.2.1.9.127.dnsbl.honeypotject.org'
		$lookup= $apikey.'.'.implode('.', array_reverse(explode ('.', $ip))).'.dnsbl.honeypotject.org';
		// check query response
		$result= explode('.', gethostbyname($lookup));

		//$this->honeypotject_blockme(); die('Restricted access');

		if($result[0] == 127) {
			// We have a result
			$a= array('activity'=>$result[1], 'threat'=>$result[2], 'type'=>$result[3]);
			$typemeaning= '';
			if($a['type'] & 0) $typemeaning.= 'Search Engine, ';
			if($a['type'] & 1) $typemeaning.= 'Suspicious, ';
			if($a['type'] & 2) $typemeaning.= 'Harvester, ';
			if($a['type'] & 4) $typemeaning.= 'Comment Spammer, ';
			$a['typemeaning']= trim($typemeaning, ', ');

			// Now determine some blocking policy
			// First set the block as NOT blocked
			$a['block']=0;

			// Assess The threat
			if(($a['type'] >= 4 && $a['threat'] > 0) || ($a['type'] < 4 && $a['threat'] > 20))
				$a['block']= 1; // set a block

			// store the info into the session (joomla style)
			$session= &JFactory::getSession();
			$session->set('honeypotject', $a);
			// store the info into the session (php style)
			// $_SESSION['honeypotject']=$a;

			if($a['block']!=0) {
				$this->honeypotject_logme(); // log the information
				$this->honeypotject_blockme(); // Block the user
				die(); // kill the rest of execution
			}
		}
	}

	/**
	 * @fn honeypotject_logme
	 * Logs the threat into a text file
	 *
	 * @since 1.0
	 * @todo for Joomla 1.6/1.7 versions 1og that information db for ease of use and extraction
	 */
	function honeypotject_logme() {
		$log= fopen($_SERVER["DOCUMENT_ROOT"].'/'.(($this->params->get('honeyproject_logdirectory') == '') ? $this->params->get('log_path') : $this->params->get('honeyproject_logdirectory')).'/honeypotject.txt', 'a');
		$stamp= date('Y-m-d :: H-i-s');
		$page= $_SERVER['REQUEST_URI'];
		$ua= $_SERVER["HTTP_USER_AGENT"];
		if(!isset($_COOKIE['notabot']))
			fputs($log,"$stamp :: BLOCKED ".$_SERVER['REMOTE_ADDR']." :: ".$_SESSION['honeypotject']['type']." :: ".$_SESSION['honeypotject']['threat']." :: ".$_SESSION['honeypotject']['activity']." :: $page :: $ua\n");
		else
			fputs($log,"$stamp :: UNBLCKD ".$_SERVER['REMOTE_ADDR']." :: $page :: $ua\n");
		fclose($log);
	}

	/**
	 * @fn honeypotject_blockme
	 *
	 * If a threat has been found
	 * blocks the access, still leaving a javascript generated link that false positive users can use to
	 * continue browsing. If the links is clicked a 'notabot' cookie is set.
	 *
	 * the remote user will get the infection warning message, but will be able to navigate
	 *
	 * @since 1.0
	 */
	function honeypotject_blockme() {
		header('HTTP/1.0 403 Forbidden');
		echo '<html><body>';
		$this->honeypotject_infected(); // inform the user that he might be infected
		// write the javascript needed to let the user in and later log it.
		$js='<script type="text/javascript">
			function setcookie(name, value, expires, path, domain, secure) {
			// set time, in milliseconds
			var today= new Date();
			today.setTime(today.getTime());
			if(expires) {
			expires= expires * 1000 * 60 * 60 * 24; }
			var expires_date= new Date(today.getTime() + (expires));
			document.cookie= name + "=" +escape(value) +
			((expires) ? ";expires=" + expires_date.toGMTString() : "") +
			((path) ? ";path=" + path : "") +
			((domain) ? ";domain=" + domain : "") +
			((secure) ? ";secure" : ""); }
			function letmein() {
			setcookie("notabot", "true", 1, "/", "", "");
			location.reload(true); }
			</script>
			<br />';
		//output the body
		echo $js.JText::_('PLG_HONEYPOTJECT_LET_ME_IN');
	}

	/**
	 * @fn honeypotject_infected
	 *
	 * Displays Infection Message
	 *
	 * @since 1.0
	 * @todo give the user a possibility of closing the div by inserting some javascript into the warning div
	 * @todo move the html code from the langage files to a default tmpl file
	 */
	function honeypotject_infected() {
		$ip= $_SERVER['REMOTE_ADDR'];
		$days= $_SESSION['honeypotject']['activity'];
		$honeypotject_css= JURI::root()."plugins/system/honeypotject/media/css/honeypotject.css";
		$infected_msg= JText::_('PLG_HONEYPOTJECT_INFECTED');
		$honeypotject_warning= '<style type="text/css" media="all">@import "'.$honeypotject_css.'";</style>'.$infected_msg;
		echo $honeypotject_warning;
	}
}
