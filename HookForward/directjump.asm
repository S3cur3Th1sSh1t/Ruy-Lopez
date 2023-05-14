extern ruylopez
global directjump

segment .text

directjump: ; we dont need to align the Stack, as the function that Called NtCreateSection will have done that already.
    jmp ruylopez      
