# mbedtls-rsa-inprogress
In-Progress work on MBED TLS power analysis (hopefully?) attack

End goal is a fully working attack that can be published as a hands-on tutorial (alongisde various other ChipWhisperer tutorials, see https://chipwhisperer.readthedocs.io/en/latest/tutorials.html ).

## MBED-TLS expmod implementation

The expmod function can be seen in https://github.com/ARMmbed/mbed-crypto/blob/master/library/bignum.c . The comments for that function suggest a sliding window is used ('Sliding-window exponentiation: X = A^E mod N  (HAC 14.85)'). The ref to HAC 14.85 (http://cacr.uwaterloo.ca/hac/about/chap14.pdf) directly points to sliding window algorithm.

This suggests we could attack it given https://eprint.iacr.org/2017/627.pdf . However, in reality a fixed window is used. in the code.

This appears to be similar/same implementation to that attacked in https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-alam.pdf.

The relevant code for the function we are attacking is shown below:

```C
    nblimbs = E->n;
    bufsize = 0;
    nbits   = 0;
    wbits   = 0;
    state   = 0;
    
    int cnt = -1;
    
    if(global_en_triger){
        if(cnt == -1){
            trigger_high();
        }
    }

    while( 1 )
    {
        if( bufsize == 0 )
        {
            if( nblimbs == 0 )
                break;

            nblimbs--;

            bufsize = sizeof( mbedtls_mpi_uint ) << 3;
        }

        bufsize--;

        ei = (E->p[nblimbs] >> bufsize) & 1;

        /*
         * skip leading 0s
         */
        if( ei == 0 && state == 0 )
            continue;

        if( ei == 0 && state == 1 )
        {
            /*
             * out of window, square X
             */
            MBEDTLS_MPI_CHK( mpi_montmul( X, X, N, mm, &T ) );
            continue;
        }

        /*
         * add ei to current window
         */
        state = 2;

        nbits++;
        wbits |= ( ei << ( wsize - nbits ) );

        if( nbits == wsize )
        {
            if(global_en_triger){
                if(cnt == 0){
                    trigger_high();
                }
            }
            /*
             * X = X^wsize R^-1 mod N
             */
            for( i = 0; i < wsize; i++ )
                MBEDTLS_MPI_CHK( mpi_montmul( X, X, N, mm, &T ) );

            /*
             * X = X * W[wbits] R^-1 mod N
             */
            MBEDTLS_MPI_CHK( mpi_montmul( X, &W[wbits], N, mm, &T ) );

            if(global_en_triger){
                if(cnt == 0){
                    trigger_low();
                    trigger_low();
                }
            }

            if(global_en_triger)cnt--;
            state--;
            nbits = 0;
            wbits = 0;
            
        }
    }
    
    if(global_en_triger){
        trigger_low();
    }

    /*
     * process the remaining bits
     */
    for( i = 0; i < nbits; i++ )
    {
        MBEDTLS_MPI_CHK( mpi_montmul( X, X, N, mm, &T ) );

        wbits <<= 1;

        if( ( wbits & ( one << wsize ) ) != 0 )
            MBEDTLS_MPI_CHK( mpi_montmul( X, &W[1], N, mm, &T ) );
    }

    /*
     * X = A^E * R * R^-1 mod N = A^E mod N
     */
    MBEDTLS_MPI_CHK( mpi_montred( X, N, mm, &T ) );

    if( neg && E->n != 0 && ( E->p[0] & 1 ) != 0 )
    {
        X->s = -1;
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( X, N, X ) );
    }
````

Power traces have been recorded by changing the value of ```cnt```. The setting of ```-1``` records the entire main loop, but NOT the 'process remining bits'.

Otherwise only the window functions are recorded. Data is described further below.


## How Data is Generated


MBED-TLS is called as in the same setup as the ChipWhisperer RSA fault attack tutorial (see https://chipwhisperer.readthedocs.io/en/latest/tutorials/fault_5-openadc-cwlitearm.html#tutorial-fault-5-openadc-cwlitearm).

The library is called as follows:

	simpleserial_mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa_ctx, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 32, hash, buf);

This eventually causes two calls to this function:

	int mbedtls_mpi_exp_mod( mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *E, const mbedtls_mpi *N, mbedtls_mpi *_RR )

You can see the source in bignum.c (github link: https://github.com/ARMmbed/mbed-crypto/blob/master/library/bignum.c).

The value 'E' will be the private exponent. The function is called twice, the first time with the value DP, the second time with DQ. These values are defined as follows:

	#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
	                "3C94D22288ACD763FD8E5600ED4A702D" \
	                "F84198A5F06C2E72236AE490C93F07F8" \
	                "3CC559CD27BC2D1CA488811730BB5725"
	
	#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
	                "D8AAEA56749EA28623272E4F7D0592AF" \
	                "7C1F1313CAC9471B5C523BFE592F517B" \
	                "407A1BD76C164B93DA2D32A383E58357"


We only record the first call, so you are seeing the value of RSA_DP. This is loaded into memory such that 0x25 is lowest byte (i=0 array index).

## Recorded Data

* rsa_full.npy - full trace running over DP, as mentioned does not include 'process remaining bits'.
* rsa_trace_11000.npy - first window processed. Processes a window wbits = 0x18 (11000b)
* rsa-trace_11010.npy - second window processed. Processes a window ```wbits`` = 0x1A (11010b).

The window details are provided to make it easier to see just a window itself.

Note for all the recordings a breakpoint is used to stop the system after the trigger goes low. Thus they do not include additional processing below the "trigger_low()" portion in the code.

## Colab

See https://colab.research.google.com/drive/1SAv-jpnBqTe2Pf6vKL4S54C6adHryj7j for in-process colab notebook.

## Plotting

If using Jupyter, suggest to use holoviews with decimate/datashade plugins to speed up plots of the large (6M) point trace:

	import numpy as np

	rsa_trace_full = np.load('rsa_full.npy')
	rsa_trace_11000 = np.load('rsa_trace_11000.npy')
	rsa_trace_11010 = np.load('rsa_trace_11010.npy')

	import holoviews as hv
	from holoviews.operation import decimate
	from holoviews.operation.datashader import datashade
	hv.extension('bokeh')
	datashade(hv.Curve(rsa_trace_full)).opts(width=900, height=600)

## Simple Things

You can see differences in the two windows for example, but haven't fully brought that down...
