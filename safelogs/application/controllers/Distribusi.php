<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Distribusi extends CI_Controller {

    public function index()
    {
         $this->load->view('dashboard/v_distribusi');
    }
}
