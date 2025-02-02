# from transformers import AutoTokenizer, AutoModelForCausalLM
# import logging
# from google.cloud import aiplatform

# # Load the LLM
# tokenizer = AutoTokenizer.from_pretrained("EleutherAI/gpt-neo-125M")
# model = AutoModelForCausalLM.from_pretrained("EleutherAI/gpt-neo-125M")
# if tokenizer.pad_token is None:
#     tokenizer.add_special_tokens({'pad_token': '[PAD]'})
#     tokenizer.pad_token = '[PAD]'
#     model.resize_token_embeddings(len(tokenizer))

# def analyze_with_llm():
#     logging.info("Started analyzing with LLM")
    
#     # Check and fallback for static features
#     features = {
#         "static_features": {
#             "disassembled_code":  "  ;-- eip:\r\n/ 501: entry0 ();\r\n| afv: vars(12:sp[0x18..0x60])\r\n| 0x004b5eec      55             push ebp\r\n| 0x004b5eed      8bec           mov ebp, esp\r\n| 0x004b5eef      83c4a4         add esp, 0xffffffa4\r\n| 0x004b5ef2      53             push ebx\r\n| 0x004b5ef3      56             push esi\r\n| 0x004b5ef4      57             push edi\r\n| 0x004b5ef5      33c0           xor eax, eax\r\n| 0x004b5ef7      8945c4         mov dword [var_3ch], eax\r\n| 0x004b5efa      8945c0         mov dword [var_40h], eax\r\n| 0x004b5efd      8945a4         mov dword [var_5ch], eax\r\n| 0x004b5f00      8945d0         mov dword [var_30h], eax\r\n| 0x004b5f03      8945c8         mov dword [var_38h], eax\r\n| 0x004b5f06      8945cc         mov dword [var_34h], eax\r\n| 0x004b5f09      8945d4         mov dword [var_2ch], eax\r\n| 0x004b5f0c      8945d8         mov dword [var_28h], eax\r\n| 0x004b5f0f      8945ec         mov dword [var_14h], eax\r\n| 0x004b5f12      b8b8144b00     mov eax, 0x4b14b8\r\n| 0x004b5f17      e8b072f5ff     call 0x40d1cc\r\n| 0x004b5f1c      33c0           xor eax, eax\r\n| 0x004b5f1e      55             push ebp\r\n| 0x004b5f1f      68e2654b00     push 0x4b65e2\r\n| 0x004b5f24      64ff30         push dword fs:[eax]\r\n| 0x004b5f27      648920         mov dword fs:[eax], esp\r\n| 0x004b5f2a      33d2           xor edx, edx\r\n| 0x004b5f2c      55             push ebp\r\n| 0x004b5f2d      689e654b00     push 0x4b659e\r\n| 0x004b5f32      64ff32         push dword fs:[edx]\r\n| 0x004b5f35      648922         mov dword fs:[edx], esp\r\n| 0x004b5f38      a134e64b00     mov eax, dword [0x4be634]             ; [0x4be634:4]=0\r\n| 0x004b5f3d      e8a29dffff     call 0x4afce4\r\n| 0x004b5f42      e8f598ffff     call 0x4af83c\r\n| 0x004b5f47      8d55ec         lea edx, [var_14h]\r\n| 0x004b5f4a      33c0           xor eax, eax\r\n| 0x004b5f4c      e84fcdf6ff     call 0x422ca0\r\n| 0x004b5f51      8b55ec         mov edx, dword [var_14h]\r\n| 0x004b5f54      b8841d4c00     mov eax, 0x4c1d84\r\n| 0x004b5f59      e8a21ef5ff     call 0x407e00\r\n| 0x004b5f5e      6a02           push 2                                ; 2\r\n| 0x004b5f60      6a00           push 0\r\n| 0x004b5f62      6a01           push 1                                ; 1\r\n| 0x004b5f64      8b0d841d4c00   mov ecx, dword [0x4c1d84]             ; [0x4c1d84:4]=0\r\n| 0x004b5f6a      b201           mov dl, 1\r\n| 0x004b5f6c      a1ec384200     mov eax, dword [0x4238ec]             ; [0x4238ec:4]=0x423944 \"8?B\" ; \"D9B\"\r\n| 0x004b5f71      e8d2def6ff     call 0x423e48\r\n| 0x004b5f76      a3881d4c00     mov dword [0x4c1d88], eax             ; [0x4c1d88:4]=0\r\n| 0x004b5f7b      33d2           xor edx, edx\r\n| 0x004b5f7d      55             push ebp\r\n| 0x004b5f7e      684a654b00     push 0x4b654a                         ; 'JeK'\r\n| 0x004b5f83      64ff32         push dword fs:[edx]\r\n| 0x004b5f86      648922         mov dword fs:[edx], esp\r\n| 0x004b5f89      e82a9effff     call 0x4afdb8\r\n| 0x004b5f8e      a3901d4c00     mov dword [0x4c1d90], eax             ; [0x4c1d90:4]=0\r\n| 0x004b5f93      a1901d4c00     mov eax, dword [0x4c1d90]             ; [0x4c1d90:4]=0\r\n| 0x004b5f98      83780c01       cmp dword [eax + 0xc], 1\r\n| 0x004b5f9c      7548           jne 0x4b5fe6\r\n| // true: 0x004b5fe6  false: 0x004b5f9e\r\n| 0x004b5f9e      a1901d4c00     mov eax, dword [0x4c1d90]             ; [0x4c1d90:4]=0\r\n| 0x004b5fa3      ba28000000     mov edx, 0x28                         ; '(' ; 40\r\n| 0x004b5fa8      e8c7e7f6ff     call 0x424774\r\n| 0x004b5fad      8b15901d4c00   mov edx, dword [0x4c1d90]             ; [0x4c1d90:4]=0\r\n| 0x004b5fb3      3b4228         cmp eax, dword [edx + 0x28]\r\n| 0x004b5fb6      752e           jne 0x4b5fe6\r\n| // true: 0x004b5fe6  false: 0x004b5fb8\r\n| 0x004b5fb8      8d55e4         lea edx, [var_1ch]\r\n| 0x004b5fbb      a1881d4c00     mov eax, dword [0x4c1d88]             ; [0x4c1d88:4]=0\r\n| 0x004b5fc0      8b08           mov ecx, dword [eax]\r\n| 0x004b5fc2      ff5104         call dword [ecx + 4]                  ; 4\r\n| 0x004b5fc5      837de800       cmp dword [var_18h], 0\r\n| 0x004b5fc9      7520           jne 0x4b5feb\r\n| // true: 0x004b5feb  false: 0x004b5fcb\r\n| 0x004b5fcb      8d55dc         lea edx, [var_24h]\r\n| 0x004b5fce      a1881d4c00     mov eax, dword [0x4c1d88]             ; [0x4c1d88:4]=0\r\n| 0x004b5fd3      8b08           mov ecx, dword [eax]\r\n| 0x004b5fd5      ff5104         call dword [ecx + 4]                  ; 4\r\n| 0x004b5fd8      8b45dc         mov eax, dword [var_24h]\r\n| 0x004b5fdb      8b15901d4c00   mov edx, dword [0x4c1d90]             ; [0x4c1d90:4]=0\r\n| 0x004b5fe1      3b4210         cmp eax, dword [edx + 0x10]\r\n| 0x004b5fe4      7305           jae 0x4b5feb\r\n| // true: 0x004b5feb  false: 0x004b5fe6\r\n| 0x004b5fe6      e8119cffff     call 0x4afbfc\r\n| // true: 0x004b5feb\r\n| 0x004b5feb      a1901d4c00     mov eax, dword [0x4c1d90]             ; [0x4c1d90:4]=0\r\n| 0x004b5ff0      8b5020         mov edx, dword [eax + 0x20]\r\n| 0x004b5ff3      a1881d4c00     mov eax, dword [0x4c1d88]             ; [0x4c1d88:4]=0\r\n| 0x004b5ff8      e833def6ff     call 0x423e30\r\n| 0x004b5ffd      baa01d4c00     mov edx, 0x4c1da0\r\n| 0x004b6002      b940000000     mov ecx, 0x40                         ; '@' ; 64\r\n| 0x004b6007      a1881d4c00     mov eax, dword [0x4c1d88]             ; [0x4c1d88:4]=0\r\n| 0x004b600c      e8f7ddf6ff     call 0x423e08\r\n| 0x004b6011      b8a01d4c00     mov eax, 0x4c1da0\r\n| 0x004b6016      8b15c0a44b00   mov edx, dword [0x4ba4c0]             ; [0x4ba4c0:4]=0x4b9310 str.Inno_Setup_Setup_Data__6.1.0___u_\r\n| 0x004b601c      b940000000     mov ecx, 0x40                         ; '@' ; 64\r\n| 0x004b6021      e81620f5ff     call 0x40803c\r\n| 0x004b6026      7405           je 0x4b602d\r\n| // true: 0x004b602d  false: 0x004b6028\r\n| 0x004b6028      e8cf9bffff     call 0x4afbfc\r\n| // true: 0x004b602d\r\n| 0x004b602d      33c0           xor eax, eax\r\n| 0x004b602f      55             push ebp\r\n| 0x004b6030      68f2604b00     push 0x4b60f2\r\n| 0x004b6035      64ff30         push dword fs:[eax]\r\n| 0x004b6038      648920         mov dword fs:[eax], esp\r\n| 0x004b603b      a1204e4200     mov eax, dword [0x424e20]             ; [0x424e20:4]=0x424e78 \"HHB\" ; \"xNB\"\r\n| 0x004b6040      50             push eax\r\n| 0x004b6041      8b0d881d4c00   mov ecx, dword [0x4c1d88]             ; [0x4c1d88:4]=0\r\n| 0x004b6047      b201           mov dl, 1\r\n| 0x004b6049      a1b8444200     mov eax, dword [0x4244b8]             ; [0x4244b8:4]=0x424510\r\n| 0x004b604e      e83de8f6ff     call 0x424890\r\n| 0x004b6053      a3e41d4c00     mov dword [0x4c1de4], eax             ; [0x4c1de4:4]=0\r\n| 0x004b6058      33c0           xor eax, eax\r\n| 0x004b605a      55             push ebp\r\n| 0x004b605b      68e1604b00     push 0x4b60e1\r\n| 0x004b6060      64ff30         push dword fs:[eax]\r\n| 0x004b6063      648920         mov dword fs:[eax], esp\r\n| 0x004b6066      6a1e           push 0x1e                             ; 30\r\n| 0x004b6068      6a04           push 4                                ; 4\r\n| 0x004b606a      ba481c4c00     mov edx, 0x4c1c48                     ; 'H\\x1cL'\r\n| 0x004b606f      b92f010000     mov ecx, 0x12f                        ; 303\r\n| 0x004b6074      a1e41d4c00     mov eax, dword [0x4c1de4]             ; [0x4c1de4:4]=0\r\n| 0x004b6079      e8a2fdf6ff     call 0x425e20\r\n| 0x004b607e      a1d01c4c00     mov eax, dword [0x4c1cd0]             ; [0x4c1cd0:4]=0\r\n| 0x004b6083      a37c1d4c00     mov dword [0x4c1d7c], eax             ; [0x4c1d7c:4]=0\r\n| 0x004b6088      6b057c1d4c..   imul eax, dword [0x4c1d7c], 0x3d\r\n| 0x004b608f      e844f3f4ff     call 0x4053d8\r\n| 0x004b6094      a3781d4c00     mov dword [0x4c1d78], eax             ; [0x4c1d78:4]=0\r\n| 0x004b6099      8b1d7c1d4c00   mov ebx, dword [0x4c1d7c]             ; [0x4c1d7c:4]=0\r\n| 0x004b609f      4b             dec ebx\r\n| 0x004b60a0      85db           test ebx, ebx\r\n| 0x004b60a2      7c25           jl 0x4b60c9\r\n| // true: 0x004b60c9  false: 0x004b60a4\r\n| 0x004b60a4      43             inc ebx\r\n| 0x004b60a5      33f6           xor esi, esi\r\n| // true: 0x004b60a7\r\n| 0x004b60a7      6a06           push 6                                ; 6\r\n| 0x004b60a9      6a04           push 4                                ; 4\r\n| 0x004b60ab      6bc63d         imul eax, esi, 0x3d\r\n| 0x004b60ae      8b15781d4c00   mov edx, dword [0x4c1d78]             ; [0x4c1d78:4]=0\r\n| 0x004b60b4      03d0           add edx, eax\r\n| 0x004b60b6      b93d000000     mov ecx, 0x3d                         ; '=' ; 61\r\n| 0x004b60bb      a1e41d4c00     mov eax, dword [0x4c1de4]             ; [0x4c1de4:4]=0\r\n| 0x004b60c0      e85bfdf6ff     call 0x425e20\r\n| 0x004b60c5      46             inc esi\r\n| 0x004b60c6      4b             dec ebx\r\n| 0x004b60c7      75de           jne 0x4b60a7\r\n| // true: 0x004b60a7  false: 0x004b60c9\r\n| 0x004b60c9      33c0           xor eax, eax\r\n| 0x004b60cb      5a             pop edx\r\n| 0x004b60cc      59             pop ecx\r\n| 0x004b60cd      59             pop ecx\r\n| 0x004b60ce      648910         mov dword fs:[eax], edx\r\n| 0x004b60d1      68e8604b00     push 0x4b60e8\r\n| 0x004b60d6      a1e41d4c00     mov eax, dword [0x4c1de4]             ; [0x4c1de4:4]=0\r\n| 0x004b60db      e808fcf4ff     call 0x405ce8\r\n\\ 0x004b60e0      c3             ret\r\n\r\n",
#             "extracted_functions": [
#                 "kernel32.dll!VirtualAlloc",
#                 "kernel32.dll!CreateThread",
#                 "advapi32.dll!RegSetValueExW",
#                 "kernel32.dll!WriteProcessMemory",
#                 "user32.dll!MessageBoxA"
#             ],
#             "strings": [
#                 "HTTP/1.1 POST /malicious/path",
#                 "/bin/sh",
#                 "c:\\temp\\payload.exe",
#                 "Base64 encoded payload: VGhpcyBpcyBhIHRlc3Q=",
#                 "Process injection detected",
#                 "Malware activity log: %APPDATA%\\malicious.log"
#             ],
#             "file_metadata": {
#                 "size_in_bytes": "1048576",
#                 "is_packed": "true",
#                 "packer_name": "UPX",
#                 "creation_timestamp": "2025-01-10T12:30:45Z"
#             }
#         }
#     }
#     static_report = features.get("static_features", {})
#     if not static_report:
#         logging.warning("Static report is empty. Using fallback content.")
#         static_report = "No meaningful static analysis features were extracted."

#     # Prepare prompt
#     prompt = f"""
#     Based on the following features extracted from static and dynamic analysis of a file:
#     Static Analysis Summary: {static_report}

#     Please analyze and conclude:
#     - Whether the file is malicious or benign.
#     - Provide reasoning and evidence to support your conclusion.
#     - Suggestions for further investigation or mitigation.
#     """
    
#     # Debug the prepared prompt
#     logging.debug(f"Prompt being sent to the model: {prompt}")

#     # Tokenize input
#     inputs = tokenizer(prompt, return_tensors="pt", padding=True, truncation=True)
#     logging.debug(f"Tokenized input: {inputs}")

#     # Generate response
#     outputs = model.generate(
#     inputs["input_ids"],
#     attention_mask=inputs["attention_mask"],
#     max_new_tokens=150,  # Limit output length
#     do_sample=False,  # Disable sampling for deterministic results
#     temperature=0.7,
#     repetition_penalty=1.5,  # Penalize repetitive sequences
#     pad_token_id=tokenizer.pad_token_id
#     )

#     result = tokenizer.decode(outputs[0], skip_special_tokens=True)
#     logging.info("LLM analysis completed.")

# # Extract relevant portion of the response
#     start_idx = result.find("1. File classification:")
#     if start_idx != -1:
#         result = result[start_idx:]
#     return result

from google.cloud import aiplatform

def analyze_with_llm(static_report, dynamic_report):
    # Initialize the AI Platform client
    aiplatform.init(project="valid-octagon-448315-b4", location="us-central1")

    # Prepare a prompt for the LLM
    prompt = f"""
    You are a cybersecurity expert. Analyze the following JSON reports:
    1. Determine if the file is malware or benign.
    2. Provide specific reasons for your prediction.

    Static Report:
    {static_report[:500]}  # Limit to 500 characters for efficiency.

    Dynamic Report:
    {dynamic_report[:500]}
    """

    # Send the prompt to the LLM endpoint
    endpoint = aiplatform.Endpoint(endpoint_name="projects/your-project-id/locations/us-central1/endpoints/your-endpoint-id")
    response = endpoint.predict(
        instances=[{"content": prompt}],
        parameters={"temperature": 0.7, "maxOutputTokens": 512}
    )

    # Extract and return the result
    return response.predictions[0].get("content")
