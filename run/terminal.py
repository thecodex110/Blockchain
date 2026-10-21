import runpy

if __name__ == "__main__":
    runpy.run_module("blockchain_lite.cli.terminal", run_name="__main__", alter_sys=True)
