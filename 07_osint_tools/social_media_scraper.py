import snscrape.modules.twitter as sntwitter
import snscrape.modules.reddit as snreddit
import pandas as pd
import argparse
import json
from datetime import datetime

# function that uses snscrape to parse through the internet for info
def scrape_twitter(username, limit=10, since=None, until=None):
    tweets = []
    for i, tweet in enumerate(sntwitter.TwitterUserScraper(username).get_items()):
        if i >= limit:
            break

        if since and tweet.date < since:
            continue
        if until and tweet.date > until:
            continue

        tweets.append({
            "date": tweet.date.strftime("%Y-%m-%d %H:%M:%S"),
            "content": tweet.content,
            "url": tweet.url
        })
    return tweets

# function that parses for info through reddit
def scrape_reddit(username, limit=10, since=None, until=None):
    posts = []
    for i, post in enumerate(snreddit.RedditUserScraper(username).get_items()):
        if i >= limit:
            break

        if since and post.date < since:
            continue
        if until and post.date > until:
            continue

        posts.append({
            "date": post.date.strftime("%Y-%m-%d %H:%M:%S"),
            "title": getattr(post, "title", ""),
            "url": post.url,
            "content": getattr(post, "selftext", "")
        })
    return posts

# function that saves results into either csv or json
def save_results(data, platform, username, output_format="csv"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{platform}_{username}_posts_{timestamp}"

    if output_format == "csv":
        pd.DataFrame(data).to_csv(f"{filename}.csv", index=False)
        print(f"|+| Saved {len(data)} items to {filename}.csv")
    elif output_format == "json":
        with open(f"{filename}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"|+| Saved {len(data)} items to {filename}.json")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Social Media Scraper (Twitter/X, Reddit)")
    parser.add_argument("platform", choices=["twitter", "reddit"], help="Platform to scrape")
    parser.add_argument("username", help="Username/handle to scrape")
    parser.add_argument("-n", "--number", type=int, default=10, help="Number of posts to fetch")
    parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv", help="Output format")
    parser.add_argument("--since", help="Only fetch posts after this date (YYYY-MM-DD)")
    parser.add_argument("--until", help="Only fetch posts before this date (YYYY-MM-DD)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    since = datetime.strptime(args.since, "%Y-%m-%d") if args.since else None
    until = datetime.strptime(args.until, "%Y-%m-%d") if args.until else None

    data = []
    try:
        if args.platform == "twitter":
            data = scrape_twitter(args.username, args.number, since, until)
        elif args.platform == "reddit":
            data = scrape_reddit(args.username, args.number, since, until)

        if args.verbose:
            for idx, item in enumerate(data, 1):
                print(f"\n[{idx}] {item['date']}\nURL: {item['url']}\n{item.get('title','')}\n{item['content']}\n")

        save_results(data, args.platform, args.username, args.format)

    except Exception as e:
        print(f"|!| Error: {e}")

if __name__ == "__main__":
    main()
