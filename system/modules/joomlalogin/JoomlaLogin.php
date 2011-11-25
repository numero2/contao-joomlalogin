<?php if (!defined('TL_ROOT')) die('You can not access this file directly!');

/**
 * Contao Open Source CMS
 * Copyright (C) 2005-2010 Leo Feyer
 *
 * Formerly known as TYPOlight Open Source CMS.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, please visit the Free
 * Software Foundation website at <http://www.gnu.org/licenses/>.
 *
 * PHP version 5
 * @copyright  2011 numero2 - Agentur für Internetdienstleistungen
 * @author     numero2 (http://www.numero2.de)
 * @package    joomlalogin
 * @license    LGPL
 */


class JoomlaLogin extends Frontend {

    
    /**
    * JoomlaLogin::importUser
    *
    * Called by the "importUser"-Hook if a user trying to log in
    * who is not existing in tl_member or tl_user
    *
    * @param sUser
    * @param sPass
    * @param sTable
    * @returns bool
    **/
    public function importUser( $sUser=NULL, $sPass=NULL, $sTable=NULL ) {

        global $objPage;

        // get list of user tables
        $aUserTables = array();
        
        if( empty($GLOBALS['TL_CONFIG']['joomlaUserTables']) ) {
            $this->log('No tables for logins defined', 'JoomlaLogin importUser()', TL_ERROR);
            return false;
        } else {
        
            $aUserTables = explode(',',$GLOBALS['TL_CONFIG']['joomlaUserTables']);
        }

        $oJUser = NULL;

        foreach( $aUserTables as $tableName ) {

            $oJUser = $this->Database->prepare("SELECT password,name,email,usertype,registerDate,lastvisitDate,block FROM `".trim($tableName)."` WHERE username=?")->limit(1)->execute($sUser);

            if( $oJUser->numRows )
                break;
        }

        if( $oJUser->numRows ) {
        
            $aPassParts = explode(':',$oJUser->password);
        
            // check if password matches
            if( md5($sPass.$aPassParts[1]) != $aPassParts[0] ) {
                $this->log('Joomla user "'.$sUser.'" tried to login but passwords did not match', 'JoomlaLogin importUser()', TL_ERROR);
                return false;
            }
        
            // generate password for contao tables
            $sSalt = substr( md5(uniqid().microtime(true)),0,23);
            $sCPassword = sha1($sSalt.$sPass).':'.$sSalt;

            // map joomla fields to contao fields
            switch( $oJUser->usertype ) {
            
                // normal user (tl_member)
                case 'Registered' : 

                    // assign user to defined groups
                    $sGroups = !empty($GLOBALS['TL_CONFIG']['joomlaDefaultMemberGroup']) ? $GLOBALS['TL_CONFIG']['joomlaDefaultMemberGroup'] : NULL;
                
                    try {
                        $this->Database->prepare("INSERT INTO tl_member (tstamp, firstname, email, username, password, locked, dateAdded, groups, loginCount, login) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 3, 1)")
                                       ->execute(
                                            strtotime($oJUser->registerDate)
                                        ,   $oJUser->name
                                        ,   $oJUser->email
                                        ,   $sUser
                                        ,   $sCPassword
                                        ,   $oJUser->block
                                        ,   strtotime($oJUser->registerDate)
                                        ,   $sGroups
                                        );
                        $this->log('Joomla user "'.$sUser.'" was successfully imported into contao database', 'JoomlaLogin importUser()', TL_ACCESS);
                    } catch( Exception $e ) {}

                    // frontend users can't login into backend
                    if( empty($objPage) ) {
                        $this->log('Joomla user "'.$sUser.'" is a frontend user but tried to login into backend', 'JoomlaLogin importUser()', TL_ERROR);
                        return false;
                    } else {
                        return true;
                    }

                break;

                // privileged users
                case 'Manager':
                case 'Public Backend':
                case 'Publisher':
                case 'Editor':
                case 'Author':

                    try {
                        $this->Database->prepare("INSERT INTO tl_user (tstamp, name, email, username, password, locked, dateAdded, loginCount, admin ) VALUES (?, ?, ?, ?, ?, ?, ?, 3, 0)")
                                       ->execute(
                                            strtotime($oJUser->registerDate)
                                        ,   $oJUser->name
                                        ,   $oJUser->email
                                        ,   $sUser
                                        ,   $sCPassword
                                        ,   $oJUser->block
                                        ,   strtotime($oJUser->registerDate)
                                        );
                        $this->log('Joomla user "'.$sUser.'" was successfully imported into contao database', 'JoomlaLogin importUser()', TL_ACCESS);
                    } catch( Exception $e ) {}

                    // backend users can't login into a frontend page
                    if( !empty($objPage) ) {
                        $this->log('Joomla user "'.$sUser.'" is a backend user but tried to login into frontend', 'JoomlaLogin importUser()', TL_ERROR);
                        return false;
                    } else {
                        return true;
                    }

                break;
                
                // administrators
                case 'Administrator':
                case 'Super Administrator' :

                    try {
                        $this->Database->prepare("INSERT INTO tl_user (tstamp, name, email, username, password, locked, dateAdded, loginCount, admin ) VALUES (?, ?, ?, ?, ?, ?, ?, 3, 1)")
                                       ->execute(
                                            strtotime($oJUser->registerDate)
                                        ,   $oJUser->name
                                        ,   $oJUser->email
                                        ,   $sUser
                                        ,   $sCPassword
                                        ,   $oJUser->block
                                        ,   strtotime($oJUser->registerDate)
                                        );
                        $this->log('Joomla user "'.$sUser.'" was successfully imported into contao database', 'JoomlaLogin importUser()', TL_ACCESS);
                    } catch( Exception $e ) {}

                    // backend users can't login into a frontend page
                    if( !empty($objPage) ) {
                        $this->log('Joomla user "'.$sUser.'" is a backend user but tried to login into frontend', 'JoomlaLogin importUser()', TL_ERROR);
                        return false;
                    } else {
                        return true;
                    }

                break;
            }
        }
    
        return false;
    }
}

?>