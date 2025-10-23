# note ngày 11/10/2025

1. l0 với l1 -l2-l3.. phải lồng vơí nhau

2. xem pattern của các loại lỗi
ví dụ mỗi loại cwe chỗ dòng flaw nó có pattern gì thì ghi thêm mục dictionary cho nó
map pattern theo L3 hoặc L2
--> đưa cho model để predict

cái L5 sau sẽ thành token.json, sửa lại 1 chút 

3. làm theo top down, để biết cái nào cần giữ-cái nào cần bỏ



    l0 la may cai ifndef, include..
    l1 laf cai hafm
    l2
    l3 la logivc, nhu do while, loop


note 20/10
lấy các dataset này: 
Juliet Test Suite: The largest synthetic dataset, useful for baseline training on a wide range of CWEs.

DiverseVul: A large-scale real-world dataset with strong CWE coverage, ideal for training robust models.
MegaVul: Comprehensive and continuously updated, offering rich code representations for advanced ML tasks.

Big-Vul: A f


ví dụ, mỗi cate của owasp sẽ có có 10 cwe, mỗi cwe sẽ có  1 file json cho nó, trong đó phần marking ở L3.

Quy tắc sẽ là Nếu gặp dòng comment bắt đầu bằng “/* POTENTIAL FLAW”, thì dòng ngay bên dưới đó được gắn làm “vulnerable_line” (focus).
Tạo block L3 tên vulnerable_context với metadata.block_type = "potential_flaw_context" và metadata kèm theo:
annotation_line_number, annotation (nguyên văn comment),
focus_line_number, vulnerable_line (dòng ngay dưới comment),
detected_by: "comment_potential_flaw".



thầy tôi có nói là chúng ta cần 1 cái dict chứa những loại cú pháp... có thể phát sinh lỗi



