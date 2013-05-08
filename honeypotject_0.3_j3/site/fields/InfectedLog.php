<?php
defined('_JEXEC') or die('Restricted access');
jimport('joomla.form.formfield');

JFormHelper::addFieldPath(JPATH_COMPONENT . 'D:\Devweb\xampp\htdocs\Joomla\plugins\system\honeypotject\fields');

class JFormFieldInfectedLog extends JFormField {
	protected $type= 'InfectedLog';

	public function getLabel() {
		return '<span>MON TItre</span>'; }

	public function getInput() {
		return 'TEXTE TEST'; }
}
?>