# NistJson: Open-Source Tool for JSON Processing and Software Vulnerabilities Analysis Based on NIST NVD
![NistJson Tool](TutorialImgs/NistJson1.PNG)

## Description
NistJson is a web-based Java application meticulously designed for the efficient processing, analysis, and export of Common Vulnerabilities and Exposures (CVE) data released by the National Vulnerability Database (NVD). Unlike command-line utilities or scripts, NistJson incorporates an interactive, multilingual graphical user interface (GUI), designed with Jakarta EE and PrimeFaces, providing an accessible and reproducible environment for software vulnerability analysis.

The application allows users to filter CVEs by year and keyword, correlate them with Common Weakness Enumeration (CWE) categories, and export the resulting datasets in Comma-Separated Values ​​(CSV) format. Due to its keyword filtering capabilities, it can be applied to any branch of knowledge, including eHealth security, DevSecOps processes, and academic research that requires comprehensive vulnerability assessments and reproducibility.

## Key Features

- **Intuitive UI with Flexible Configuration**: Designed for both experienced developers and non-technical users, NistJson provides an intuitive web interface for processing vulnerability data. Users can adjust parameters such as keywords, year ranges, and language preferences directly from the UI.
- **Scalable and High-Performance JSON Processing**: Leveraging the Jackson library, NistJson efficiently parses large NVD JSON datasets with minimal resource usage. It supports multi-year CVE feeds and maintains consistent performance across growing data volumes.
- **Modular and Expandable Architecture**: Built with clean object-oriented principles and a modular structure, the application can be easily extended or customized. New features, filters, or output formats can be integrated with minimal impact on the core system.
- **Advanced Filtering and Metadata Augmentation**: NistJson enables dynamic, keyword-based filtering with fully parameterizable criteria. It also enriches vulnerability entries with supplemental metadata such as CVSS metrics, health relevance, and CWE classification.
- **Internationalization and Language Switching**:Offers built-in support for multiple languages (e.g., English, Spanish), with session-based language selection using JSF resource bundles. Easy to extend by adding new locale files.
- **Sophisticated Search and Advanced Data Enrichment**: NistJson offers advanced search capabilities characterized by fully parameterizable criteria, thereby enabling precise filtering and retrieval of data. Additionally, users are empowered to augment extracted vulnerability data with supplementary metadata, enriching the depth of analysis and insights.
- **Research Reproducibility and Reliability**: By standardizing execution parameters and input data, the tool guarantees reliability and accuracy, facilitating the reproducibility of research endeavors and ensuring consistency of results across diverse studies.
- **Efficient JSON Processing with Jackson**: NistJson capitalizes on the Jackson library to proficiently parse and process large volumes of JSON data, such as that sourced from the National Vulnerability Database (NVD), ensuring optimal performance and data integrity.
- **CSV Export and Cross-Platform Compatibility**: The tool facilitates the straightforward export of processed data into CSV format for seamless integration with data analysis tools. As a Java-based application, it boasts cross-platform compatibility, enabling uninterrupted use across various operating systems without necessitating additional dependencies or configurations.
- **Platform Independence and Easy Deployment**: Packaged as a WAR file and built with Java 17 and Jakarta EE 10, NistJson runs on any standard application server (Payara, WildFly, etc.) across Windows, Linux, or macOS environments without additional dependencies.

## Installation of <a name="_hlk187925083"></a>NetBeans Ide 8.0.2

1. Run the NetBeans Ide 8.0.2 installer and press the "Customize..." button:
   
<div align="center">
  <img src="TutorialImgs/Netbeans1.png" alt="NetBeans" />
</div>

2. Enable plugins for java usage and click on “Ok” button:
<div align="center">
  <img src="TutorialImgs/Netbeans2.png" alt="NetBeans2" />
</div>

3. Click on next button:

<div align="center">
  <img src="TutorialImgs/Netbeans3.png" alt="NetBeans3" />
</div>

 4. Read and accept the terms of use, then, click on “Next” button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans4.png" alt="NetBeans4" />
</div>

 5. Don’t install Junit, and click on “Next” button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans5.png" alt="NetBeans5" />
</div>

 6. Select the installation path and click on Next button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans6.png" alt="NetBeans6" />
</div>
  
 7. Click on install button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans7.png" alt="NetBeans7" />
</div>

 8. Click on the Finish button 
    
<div align="center">
  <img src="TutorialImgs/Netbeans8.png" alt="NetBeans8" />
</div>

## Preparing java project

 1. Select the directory to which the repository will be cloned:  
    
<div align="center">
  <img src="TutorialImgs/Netbeans9.png" alt="NetBeans9" />
</div>
    
 2. Run the command git clone https://github.com/cmejia5486/nistJson.git. 
    
<div align="center">
  <img src="TutorialImgs/Netbeans10.png" alt="NetBeans10" />
</div> 

 3. Visit the NIST NVD URL https://nvd.nist.gov/vuln/data-feeds, download the data feeds in Json format and place them in the "JsonData" directory of the project. 
    
<div align="center">
  <img src="TutorialImgs/Netbeans11.png" alt="NetBeans11" />
</div> 

 4. Open the project in the previously installed NetBeans Ide 8.0.2 and click on clean and build option.
    
<div align="center">
  <img src="TutorialImgs/Netbeans12.png" alt="NetBeans12" />
</div> 


## Setting the keywords

 1. Inside the nist.main package go to the main.class class and in the list of strings you can add as many "keys" as you consider necessary, for the particular example "HEALTH" and "MEDIC" have been added.
    
<div align="center">
  <img src="TutorialImgs/Netbeans13.PNG" alt="NB13" />
</div> 

## 6.	Running the tool

 1. Right click on the project and press the "Run" button, this will process the files in JSON format and generate the processed data as output in CVS format.
    
<div align="center">
  <img src="TutorialImgs/Netbeans14.PNG" alt="NB14" />
</div> 

 2. At the end of the execution of the tool, an output like the one presented will be generated. 
<div align="center">
  <img src="TutorialImgs/Netbeans15.PNG" alt="NB15" />
</div> 

 3. The generated files will be found under the directory:  ../nistJson/results. 
<div align="center">
  <img src="TutorialImgs/Netbeans16.PNG" alt="NB16" />
</div> 


 4. Right click over the VulnerabilityDataExporter java class and select “RunFile option
<div align="center">
  <img src="TutorialImgs/Netbeans17.PNG" alt="NB17" />
</div> 

 5. Once the execution is finished without exceptions, it will issue the information message about the files with the generated metrics
<div align="center">
  <img src="TutorialImgs/Netbeans18.PNG" alt="NB18" />
</div> 

 6. The generated files will be found under the directory:  ../nistJson/spss


## Demo
[Demo video](https://youtu.be/LmwGtRXYmxI?si=MOAlIm66rHSoARXy)

## Technical Documentation Manual
[JavaDoc](target/reports/apidocs/index.html)

## **License:**
This project is licensed under the GNU General Public License Version 3 - see the [LICENSE](https://github.com/cmejia5486/nistJson/blob/main/LICENSE) file for details. 

## **Contact:**
**Carlos M. Mejía-Granda** 

- E-mail: <carlosmichael.mejiag@um.es>
- LinkedIn: [Carlos Mejía Granda](https://www.linkedin.com/in/carlos-mej%C3%ADa-granda-70239910a/).

## **Acknowledgements**

We would like to express our gratitude to the National Institute of Standards and Technology (NIST) National Vulnerability Database (NVD) for providing their data feeds in JSON format, which have been invaluable in our experiments and are included as data samples in this repository.
