import json
import tkinter as tk
import traceback

import yaml

from rain_api_core.bucket_map import BucketMap


def main():
    window = tk.Tk()
    window.title("IAM Policy Generator Sandbox")
    window.columnconfigure(0, weight=1)
    window.rowconfigure(0, weight=1)

    frm_content = tk.Frame(window)
    frm_content.columnconfigure(0, weight=1)
    frm_content.columnconfigure(1, weight=1)
    frm_content.rowconfigure(1, weight=1)
    frm_content.grid(row=0, column=0, sticky="nsew")

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

    # Bucket map panel
    tk.Label(frm_content, text="Bucket map YAML").grid(row=0, column=0)

    txt_bucketmap = tk.Text(frm_content)
    txt_bucketmap.bind(
        "<Key>",
        lambda _: window.after(1, handle_text)
    )
    txt_bucketmap.grid(row=1, column=0, sticky="nsew")

    # Policy panel
    tk.Label(frm_content, text="Policy JSON").grid(row=0, column=1)

    txt_policy = tk.Text(frm_content)
    txt_policy.grid(row=1, column=1, sticky="nsew")

    window.mainloop()


if __name__ == "__main__":
    main()
