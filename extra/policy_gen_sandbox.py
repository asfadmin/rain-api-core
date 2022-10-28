import json
import tkinter as tk
import traceback

import yaml

from rain_api_core.bucket_map import BucketMap


def main():
    window = tk.Tk()
    window.title("IAM Policy Generator Sandbox")
    window.columnconfigure([0, 1], weight=1)
    window.rowconfigure(0, minsize=800, weight=1)

    frm_bucketmap = tk.Frame()
    tk.Label(frm_bucketmap, text="Bucket map YAML").pack()
    txt_bucketmap = tk.Text(frm_bucketmap)

    def handle_text():
        text = txt_bucketmap.get("1.0", tk.END)
        try:
            bucket_map = yaml.safe_load(text)
            if bucket_map is None:
                return
            b_map = BucketMap(bucket_map)

            policy = b_map.to_iam_policy()
            policy_text = json.dumps(policy, indent=2)
            txt_policy.delete("1.0", tk.END)
            txt_policy.insert(tk.END, policy_text)
        except Exception:
            exc_text = traceback.format_exc()
            txt_policy.delete("1.0", tk.END)
            txt_policy.insert(tk.END, exc_text)

    txt_bucketmap.bind(
        "<Key>",
        lambda _: window.after(1, handle_text)
    )

    txt_bucketmap.pack(expand=True, fill=tk.BOTH)
    frm_bucketmap.grid(row=0, column=0, sticky="nsew")

    frm_policy = tk.Frame()
    tk.Label(frm_policy, text="Policy JSON").pack()
    txt_policy = tk.Text(frm_policy)

    txt_policy.pack(expand=True, fill=tk.BOTH)
    frm_policy.grid(row=0, column=1, sticky="nsew")

    window.mainloop()


if __name__ == "__main__":
    main()
