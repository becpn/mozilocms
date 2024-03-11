# MoziloCMS File Upload Vulnerability

<h2>Introduction to MoziloCMS</h2>

moziloCMS is a simple and clear flat file content management system (Flatfile-CMS). It is aimed primarily at users with low HTML knowledge and impresses with its entry-level-friendly operation.

[Download Link](https://github.com/moziloDasEinsteigerCMS/mozilo2.0/archive/master.zip)

<h2>POC</h2>

After loging in to the user account one can see the files tab on the navigation bar.

![image](https://github.com/becpn/mozilocms/assets/162958600/52d71291-e294-4a02-bedc-c96f08fef5ca)


The application restricts file uploads to disallow file types that are configured in the moziloAdmin panel.

![image](https://github.com/becpn/mozilocms/assets/162958600/09d4e3c7-83d1-4529-8eef-4f0aa5ff3edb)


![image](https://github.com/becpn/mozilocms/assets/162958600/5536b80c-fe65-4f4a-a6b1-dd62cee2d06c)


The application enforces restrictions on file uploads based on the extensions not allowed by the configuration in the moziloAdmin panel. However, it does not adequately verify file types after upload, allowing an attacker to bypass the extension check by simply changing the filename after the upload process.

![image](https://github.com/becpn/mozilocms/assets/162958600/81d733ec-0773-4963-b6b0-25e9aa8a6484)


![image](https://github.com/becpn/mozilocms/assets/162958600/bb2daf90-7e0b-4f85-bd09-2c0e601a3b9e)


![image](https://github.com/becpn/mozilocms/assets/162958600/4c344321-149c-4566-9ec6-85432a88ffad)

<h3>File Upload Code</h3>

```
if(ACTION == "files") {
            global $ADMIN_CONF;
            if(strlen($ADMIN_CONF->get("noupload")) > 0) {
                $acceptfiletypes = ".".str_replace("%2C","%2C.",$ADMIN_CONF->get("noupload"));
                $acceptfiletypes = explode("%2C",$acceptfiletypes);
            } else
                $acceptfiletypes = array();
            if(in_array(strtolower(substr($file->name,(strrpos($file->name,".")))),$acceptfiletypes))
                return 'acceptFileTypes';
        } else {
            if(!in_array(strtolower(substr($file->name,(strrpos($file->name,".")))),$acceptfiletypes))
                return 'acceptFileTypes';
```

The application applies extension checks during the upload process, but fails to implement the same checks during file renaming, thereby enabling an attacker to bypass extension restrictions by renaming the uploaded file.

<h3>File Rename Code</h3>

```
if(false !== ($newfile = getRequestValue('newfile','post',false))
            and false !== ($orgfile = getRequestValue('orgfile','post'))
            and false !== ($curent_dir = getRequestValue('curent_dir','post'))) {
        $dir = CONTENT_DIR_REL.$curent_dir."/".CONTENT_FILES_DIR_NAME."/";
        if(true !== ($error = moveFileDir($dir.$orgfile,$dir.$newfile,true))) {
            ajax_return("error",true,$error,true,"js-dialog-reload");
        }
        ajax_return("success",true);
    }
```
