# Canadian Centre for Cyber Security

## CCCS YARA Specification

The [CCCS YARA Specification](https://github.com/CybercentreCanada/cccs-yara-formatter/blob/master/CCCS_Yara.yml) has been created to define the style and format of YARA rule metadata. This ontology simplifies system integration and exchange of your yara rules with well defined fields and formats. [AssemblyLine](https://www.cyber.gc.ca/en/assemblyline) supports this specification natively and will leverage it to provide more context around YARA signature hits.

## Components

yara_validator.py:		This is the validator library. It is used to verify specified the yara rule has specified metadata information, autogenerates some of the tags and sorts the tags in the canonical order with all 'unknown' metadata information appended to the bottom.

- [CCCS_Yara.yml](https://github.com/CybercentreCanada/cccs-yara-formatter/blob/master/CCCS_Yara.yml):        This is the definition of the CCCS YARA Standard in the .yml format. (Limitation: This file is provided to show what fields are expected, currently the yara_validator dosen't use this file directly, this will be addressed in a future release.)

- [CCCS_Yara_values.yml](https://github.com/CybercentreCanada/cccs-yara-formatter/blob/master/CCCS_Yara_values.yml): File which describe the list of acceptable values for fields defined in the CCCS_Yara.yml

yara_validator_cli.py:	This is a command line interface utility. It takes a file, list of files, a folder looking for files with the .yar or .yara extention. 

Note: the library and the cli are currently designed with the assumption that each file has a single yara rule in it.

# Centre canadien pour la cybersécurité

## Spécification YARA du CCCS

La [Spécification YARA du CCCS](https://github.com/CybercentreCanada/cccs-yara-formatter/blob/master/CCCS_Yara.yml) a été créé pour définir le style et le format des attributs pour les règles YARA. Cette ontologie simplifie l'intégration des règles dans vos systèmes et l'échange de règles dans un format bien défini. [AssemblyLine](https://www.cyber.gc.ca/en/assemblyline) supporte cette spécification nativement et l'utilisera pour fournir d'avantage d'information a l'utilisateur lors du déclanchement d'une signature.

## Composantes

yara_validator.py:		La librairie de validation. Elle permet de vérifier si une règle YARA a tous les attributs nécessaires, elle auto-génère aussi certain attribut et les ordonnent selon l'ontologie. Tous les attributs supplémentaire ne faisant pas partie de la spécification sont placé a la fin.

- [CCCS_Yara.yml](https://github.com/CybercentreCanada/cccs-yara-formatter/blob/master/CCCS_Yara.yml):        Fichier de de définition de la spécification. (Limitation: Ce fichier démontre les attributs nécessaires, présentement le validateur n'utilise pas se fichier directement, ceci sera améliorer dans le future.)

- [CCCS_Yara_values.yml](https://github.com/CybercentreCanada/cccs-yara-formatter/blob/master/CCCS_Yara_values.yml): Fichier qui décrit les valeurs acceptables pour chacun des attributs définit dans CCCS_Yara.yml.

yara_validator_cli.py:	Utilitaire de validation pour la ligne de commande. Il accepte une règle, une liste de règles ou un dossier pour validé les fichiers se terminant par .yar ou .yara.  

Note:  la librairie et l'utilitaire de ligne de commande n'accepte que les fichiers qui contient un seule règle par fichier.


## Requirements

Python 3.6

All required python packages are in the requirements.txt

## yara_validator_cli.py usage

```
yara_validator_cli.py -h 
     ____ ____ ____ ____   __   __ _    ____      _    
    / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \   
   | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \  
   | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \ 
    \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\ 
    
usage: yara_validator_cli.py [-h] [-r] [-n] [-v] [-vv] [-f] [-w] [-s]
                             [-i | -c]
                             paths [paths ...]

CCCS YARA script to run the CCCS YARA validator, if the -i or -c flags are not
provided no changes will be made to the files.

positional arguments:
  paths                A list of files or folders to be analyzed.

optional arguments:
  -h, --help           show this help message and exit
  -r, --recursive      Recursively search folders provided.
  -n, --no-changes     Makes no changes and outputs potential results to the
                       output.
  -v, --verbose        Verbose mode, will print why a rule was invalid.
  -vv, --very-verbose  Very-verbose mode, will printout what rule is about to
                       be processed, the invalid rules, the reasons they are
                       invalid and all contents of the rule.
  -f, --fail           Fail mode, only prints messages about invalid rules.
  -w, --warnings       This mode will ignore warnings and proceed with other
                       behaviors if the rule is valid.
  -s, --standard       This prints the yara standard to the screen.
  -i, --in-place       Modifies valid files in place, mutually exclusive with
                       -c.
  -c, --create-files   Writes a new file for each valid file, mutually
                       exclusive with -i.
  ```
