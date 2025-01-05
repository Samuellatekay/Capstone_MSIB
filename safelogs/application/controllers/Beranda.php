<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Beranda extends CI_Controller {
	public $form_validation;
	public $session;
	public $simple_login;
	public $m_account;

    public function index()
    {
         $this->load->view('account/v_beranda');
    }
}
