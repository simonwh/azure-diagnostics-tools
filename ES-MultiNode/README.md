# ES-MultiNode template and scripts for setting up Elastic Search and Kibana on Azure

This folder contains a set of scripts and and an [**Azure Resource Manager template**](https://azure.microsoft.com/documentation/articles/resource-group-overview/) for creating a multi-node [**ElasticSearch**](https://www.elastic.co/guide/index.html) cluster on Azure VMs (running Ubuntu Linux). The cluster is protected by HTTP basic authentication.

### Preparing a machine to run Elastic Search installation scripts
First, download the current GitHub repository ([Microsoft Patterns & Practices ELK branch](https://github.com/mspnp/semantic-logging/tree/elk/)) to your machine (either by cloning the repo or downloading a ZIP file). The ARM template and scripts described here are located in the ES-MultiNode folder.

The easiest way to use the ES-MultiNode template is through a provided PowerShell script called `CreateElasticSearchCluster`. To use this script you need to install **Azure PowerShell** and **openssl** tool. The latter is needed for creating an SSH key that can be used to administer your Elastic Search cluster remotely.

> The `CreateElasticSearchCluster` script is designed to ease the use of the ES-MultiNode template from a Windows machine. It is possible to use the template on a non-Windows machine, but that scenario is beyond the scope of this article.

1. If you haven't installed it already, install [**Azure PowerShell**](http://aka.ms/webpi-azps). When prompted, click Run, then Install. PowerShell 1.3 or later is required.
 
2. The **openssl** tool is included in the distribution of [**Git for Windows**](http://www.git-scm.com/downloads). If you have not done so already, please install [Git for Windows](http://www.git-scm.com/downloads) now (default installation options are OK).

3. Assuming that Git has been installed, but not included in the system path, open PowerShell window and run the following commands:

    ```powershell
    $ENV:PATH += ";<Git installation folder>\usr\bin"
    $ENV:OPENSSL_CONF = "<Git installation folder>\usr\ssl\openssl.cnf"
    ```

    Replace the `<Git installation folder>` with the Git location on your machine; the default is `C:\Program Files\Git`. Note the semicolon character at the beginning of the first path.

4. Ensure that you are logged on to Azure (via [`Add-AzureRmAccount`](https://msdn.microsoft.com/en-us/library/mt619267.aspx) cmdlet) and that you have selected the subscription that should be used to create your Elastic Search cluster. You can verify that correct subscription is selected using `Get-AzureRmContext` and `Get-AzureRmSubscription` cmdlets.

5. If you haven't done so already, change the current directory to the ES-MultiNode folder.

### Running CreateElasticSearchCluster script
Before running the script, open the `azuredeploy-parameters.json` file and verify or provide values for script parameters. The following parameters are provided:

|Parameter Name           |Description|
|-----------------------  |--------------------------|
|dnsNameForLoadBalancerIP |This is the name that will be used to create the publicly visible DNS name for the Elastic Search cluster (by appending the Azure region domain to the provided name). For example, if this parameter value is "myBigCluster" and the chosen Azure region is West US, the resulting DNS name for the cluster will be myBigCluster.westus.cloudapp.azure.com. <br /><br />This name will also serve as a root for names for many artifacts associated with the Elastic Search cluster, such as data node names.|
|adminUsername           |The name of the administrator account for managing the Elastic Search cluster (corresponding SSH keys will be generated automatically)|
|dataNodeCount           |The number of nodes in the Elastic Search cluster. The current version of the script does not distinguish between data and query nodes; all nodes will play both roles. Defaults to 3 nodes.|
|dataDiskSize            |The size of data disks (in GB) that will be allocated for each data node. Each node will receive 4 data disks, exclusively dedicated to Elastic Search service.|
|esUserName              |The user name of the user that will be configured to have access to ES cluster (subject to HTTP basic authentication). The password is not part of parameters file and must be provided when `CreateElasticSearchCluster` script is invoked.|
|vmSizeDataNodes         |The Azure virtual machine size for Elastic Search cluster nodes. Defaults to Standard_D1.|

Now you are ready to run the script. Issue the following command:

```powershell
CreateElasticSearchCluster -ResourceGroupName <es-group-name> -Region <azure-region> -EsPassword <es-password>
```

where 

|Script Parameter Name    |Description|
|-----------------------  |--------------------------|
|`<es-group-name>`        |the name of the Azure resource group that will contain all Elastic Search cluster resources|
|`<azure-region>`         |the name of the Azure region where the Elastic Search cluster should be created|         
|`<es-password>`          |the password for the Elastic Search user|

> If you get a NullReferenceException from Test-AzureResourceGroup cmdlet, you have forgotten to log on to Azure (`Add-AzureRmAccount`).

If you get an error from running the script and you determine that the error was caused by a wrong template parameter value, correct the parameter file and run the script again with a different resource group name. You can also reuse the same resource group name and have the script clean up the old one by adding `-RemoveExistingResourceGroup` parameter to the script invocation.

### Result of running the CreateElasticSearchCluster script
After running the `CreateElasticSearchCluster` script the following main artifacts will be created. For the sake of clarity we will assume that you have used 'myBigCluster' for the value of `dnsNameForLoadBalancerIP` parameter and that the region where you created the cluster is West US.

|Artifact|Name, Location and Remarks|
|----------------------------------|----------------------------------|
|SSH key for remote administration |myBigCluster.key file (in the directory from which the CreateElasticSearchCluster was run). <br /><br />This is the key that can be used to connect to the admin node and (through the admin node) to data nodes in the cluster.|
|Admin node                        |myBigCluster-admin.westus.cloudapp.azure.com <br /><br />This is a dedicated VM for remote Elastic Search cluster administration, the only one that allows external SSH connections. It runs on the same virtual network as all the Elastic Search cluster nodes but does not run Elastic Search services.|
|Data nodes                        |myBigCluster1 … myBigCluster*N* <br /><br />Data nodes that are running Elastic Search and Kibana services. You can connect via SSH to each node, but only via the admin node.|
|ElasticSearch cluster             |http://myBigCluster.westus.cloudapp.azure.com/es/ <br /><br />The above is the primary endpoint for the Elastic Search cluster (note the /es suffix). It is protected by basic HTTP authentication (the credentials were specified esUserName/esPassword parameters of the ES-MultiNode template). The cluster has also the head plugin installed (http://myBigCluster.westus.cloudapp.azure.com/es/_plugin/head/) for basic cluster administration.|
|Kibana service                    |http://myBigCluster.westus.cloudapp.azure.com <br /><br />Kibana service is set up to show data from the created Elastic Search cluster; it is protected by the same authentication credentials that the cluster itself.|

That is it! Now you should be able to connect to your newly created Elastic Search cluster, push some data into it and view them in Kibana.