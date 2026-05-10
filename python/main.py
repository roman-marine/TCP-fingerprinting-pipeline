import argparse
from train import load_and_filter, build_partitions, run_tier1, run_tier2, run_tier3, run_tier4, run_tier4_secondary, run_p0f
from pathlib import Path
from datetime import datetime
from time import time

DATASET_PATH = "dataset.csv"


def make_output_dirs(base="results"):
    """
    Create a timestamped output directory for this run.
    Structure:
        results/
          run_YYYYMMDD_HHMMSS/
            tier1/
            tier2/
            tier3/
            tier4/tails_cluster
            tier4/secondary_clusters
            p0f/
    """
    run_id  = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    run_dir = Path(base) / run_id
    for sub in ["tier1", "tier2", "tier3", "tier4", "p0f"]:
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
        if sub == "tier4":
            (run_dir / sub / "tails_cluster").mkdir(parents=True, exist_ok=True)
            (run_dir / sub / "secondary_clusters").mkdir(parents=True, exist_ok=True)
            
    return run_dir


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Thesis evaluation pipeline for passive TCP/IP OS fingerprinting."
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run all experiments (default if no tier flags are given).",
    )
    parser.add_argument(
        "--tier1", action="store_true",
        help="Run Tier 1: OS family discrimination.",
    )
    parser.add_argument(
        "--tier2", action="store_true",
        help="Run Tier 2: Linux distribution discrimination.",
    )
    parser.add_argument(
        "--tier3", action="store_true",
        help="Run Tier 3: Debian-family discrimination.",
    )
    parser.add_argument(
        "--tier4", action="store_true",
        help="Run Tier 4: Kernel cluster discrimination.",
    )
    parser.add_argument(
        "--tier4-secondary", action="store_true",
        help="Run Tier 4 secondary: corroborating kernel cluster evaluation.",
    )
    parser.add_argument(
        "--p0f", action="store_true",
        help="Run P0f baseline evaluation.",
    )
    parser.add_argument(
        "--dataset", type=str, default=None,
        help="Override the dataset path.",
    )
    parser.add_argument(
        "--p0f-dir", type=str, default="p0f",
        help="Directory containing P0f output files (one per OS instance).",
    )
    parser.add_argument(
        "--results-dir", type=str, default="results",
        help="Base directory for run output (default: results/).",
    )
    return parser.parse_args()


def main():
    args = _parse_args()
    run_all = args.all or not any([args.tier1, args.tier2, args.tier3, args.tier4, args.tier4_secondary, args.p0f])
    run_t1  = run_all or args.tier1
    run_t2  = run_all or args.tier2
    run_t3  = run_all or args.tier3
    run_t4  = run_all or args.tier4
    run_t4s = run_all or args.tier4_secondary
    run_p0f_flag = run_all or args.p0f

    dataset_path = args.dataset or DATASET_PATH
    run_dir      = make_output_dirs(base=args.results_dir)

    print(f"Results will be saved to: {run_dir}")
    print(f"Using dataset: {dataset_path}")
    tiers_launched = ", ".join([
        t for t, run in [
            ("Tier 1", run_t1), ("Tier 2", run_t2), ("Tier 3", run_t3),
            ("Tier 4", run_t4), ("Tier 4 Secondary", run_t4s), ("P0f", run_p0f_flag),
        ] if run
    ])
    print(f"Tiers to run: {tiers_launched}")
    print()

    df         = load_and_filter(dataset_path)
    partitions = build_partitions(df)
    start_time = time()

    if run_t1:
        t = time()
        run_tier1(partitions, run_dir)
        print(f"Tier 1 completed in {time() - t:.1f}s")

    if run_t2:
        t = time()
        run_tier2(partitions, run_dir)
        print(f"Tier 2 completed in {time() - t:.1f}s")

    if run_t3:
        t = time()
        run_tier3(partitions, run_dir)
        print(f"Tier 3 completed in {time() - t:.1f}s")

    if run_t4:
        t = time()
        run_tier4(partitions, run_dir)
        print(f"Tier 4 completed in {time() - t:.1f}s")

    if run_t4s:
        t = time()
        run_tier4_secondary(partitions, run_dir)
        print(f"Tier 4 Secondary completed in {time() - t:.1f}s")

    if run_p0f_flag:
        t = time()
        p0f_dir = Path(args.p0f_dir)
        if p0f_dir.exists():
            run_p0f(partitions, run_dir, args.p0f_dir)
        else:
            print(f"P0d directory does not exist {p0f_dir}")
        
        print(f"P0f completed in {time() - t:.1f}s")

    print(f"\nDone. Results saved to: {run_dir}")
    print(f"Total time: {time() - start_time:.1f}s")


if __name__ == "__main__":
    main()
    
