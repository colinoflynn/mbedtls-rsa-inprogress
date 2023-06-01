# Complete power analysis attack on MBED-TLS 

This repo contains a complete power analysis attack on MBED-TLS. This repository contains the notebook and traces for the master thesis:
    
    ```
    @mastersthesis{side-mico-2023,
        author = {Micó Biosca, Victor},
        title = {Side channel attack against the Mbed-TLS implementation of the RSA algorithm},
        school = {Universitat de Girona},
        year = {2023},
        month = {June}
    }
    ```


This repo now contains three looks at MBED-TLS power analysis:

1. In the "husky-stm32f3" folder, the traces were captured with a CW-Husky on a STM32F3 target. The folder also includes a notebook where the complete attack is performed.
1. In the "old-stm32" folder, the traces and notes were made at SHARD 2019, and reflect a capture done with a CW-Pro on a STM32F target done by .
1. In the "new-sam4s" folder, the traces were captured with a CW-Husky on a SAM4S target.

